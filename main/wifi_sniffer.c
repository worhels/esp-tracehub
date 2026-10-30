





















#include "wifi_sniffer.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"





#define MAC_SET_CAPACITY 64
#define CHANNEL_MAX 13
#define CHANNEL_DWELL_MS 200
#define HOP_TASK_STACK 2048
#define HOP_TASK_PRIO 2

#define SNIFFER_QUEUE_SIZE 64
#define UART_TASK_STACK 4096
#define UART_TASK_PRIO 3
#define HEARTBEAT_INTERVAL_MS 2000

static const char *TAG = "wifi_sniffer";





typedef enum {
    SNIFFER_EVT_BEACON,
    SNIFFER_EVT_PROBE_REQ,
    SNIFFER_EVT_PROBE_RESP,
    SNIFFER_EVT_ASSOC_REQ,
    SNIFFER_EVT_ASSOC_RESP,
    SNIFFER_EVT_DEAUTH,
    SNIFFER_EVT_NEW_DEVICE,
} sniffer_evt_type_t;

typedef struct {
    sniffer_evt_type_t type;
    uint8_t mac[6];
    int8_t rssi;
    uint8_t channel;
    uint16_t reason;
    int64_t timestamp_s;
    char ssid[33];
} sniffer_event_msg_t;





typedef struct {
    uint8_t  mac[6];
    bool     occupied;
} mac_entry_t;

static mac_entry_t s_mac_set[MAC_SET_CAPACITY];
static uint32_t    s_mac_count = 0;

static uint32_t mac_hash(const uint8_t mac[6])
{
    uint32_t h = 0x811c9dc5u;
    for (int i = 0; i < 6; i++) {
        h ^= mac[i];
        h *= 0x01000193u;
    }
    return h;
}

static bool mac_set_insert(const uint8_t mac[6])
{
    if (s_mac_count >= MAC_SET_CAPACITY) {
        return false;
    }
    uint32_t idx = mac_hash(mac) & (MAC_SET_CAPACITY - 1);
    for (uint32_t i = 0; i < MAC_SET_CAPACITY; i++) {
        uint32_t pos = (idx + i) & (MAC_SET_CAPACITY - 1);
        if (!s_mac_set[pos].occupied) {
            memcpy(s_mac_set[pos].mac, mac, 6);
            s_mac_set[pos].occupied = true;
            s_mac_count++;
            return true;
        }
        if (memcmp(s_mac_set[pos].mac, mac, 6) == 0) {
            return false;
        }
    }
    return false;
}

static void mac_set_clear(void)
{
    memset(s_mac_set, 0, sizeof(s_mac_set));
    s_mac_count = 0;
}





static bool                  s_initialised  = false;
static volatile bool         s_running      = false;
static TaskHandle_t          s_hop_task     = NULL;
static TaskHandle_t          s_uart_task    = NULL;
static QueueHandle_t         s_event_queue  = NULL;
static wifi_sniffer_stats_t  s_stats        = {0};





typedef struct __attribute__((packed)) {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} wifi_ieee80211_hdr_t;

#define WLAN_FC_TYPE_MGMT        0x00
#define WLAN_FC_STYPE_ASSOC_REQ  0x00
#define WLAN_FC_STYPE_ASSOC_RESP 0x01
#define WLAN_FC_STYPE_PROBE_REQ  0x04
#define WLAN_FC_STYPE_PROBE_RESP 0x05
#define WLAN_FC_STYPE_BEACON     0x08
#define WLAN_FC_STYPE_DEAUTH     0x0C

static void extract_ssid(const uint8_t *body, int body_len, int fixed_len,
                         char *out_ssid, size_t out_size)
{
    out_ssid[0] = '\0';
    if (body_len <= fixed_len) {
        return;
    }
    const uint8_t *tags     = body + fixed_len;
    int            tags_len = body_len - fixed_len;
    int            offset   = 0;

    while (offset + 2 <= tags_len) {
        uint8_t tag_id  = tags[offset];
        uint8_t tag_len = tags[offset + 1];
        if (offset + 2 + tag_len > tags_len) {
            break;
        }
        if (tag_id == 0 && tag_len > 0) {
            size_t copy_len = tag_len;
            if (copy_len >= out_size) {
                copy_len = out_size - 1;
            }
            memcpy(out_ssid, &tags[offset + 2], copy_len);
            out_ssid[copy_len] = '\0';
            return;
        }
        offset += 2 + tag_len;
    }
}





static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT || s_event_queue == NULL) {
        return;
    }

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const wifi_pkt_rx_ctrl_t     *rx  = &pkt->rx_ctrl;
    const uint8_t                *payload = pkt->payload;
    const int                     len     = rx->sig_len;

    if (len < (int)sizeof(wifi_ieee80211_hdr_t)) {
        return;
    }

    const wifi_ieee80211_hdr_t *hdr = (const wifi_ieee80211_hdr_t *)payload;
    uint8_t fc_type    = (hdr->frame_ctrl & 0x000C) >> 2;
    uint8_t fc_subtype = (hdr->frame_ctrl & 0x00F0) >> 4;

    if (fc_type != WLAN_FC_TYPE_MGMT) {
        return;
    }

    s_stats.total_frames++;

    const uint8_t *src_mac = hdr->addr2;
    int rssi  = rx->rssi;
    int chan  = rx->channel;

    const uint8_t *body     = payload + sizeof(wifi_ieee80211_hdr_t);
    int            body_len = len - (int)sizeof(wifi_ieee80211_hdr_t);


    if (mac_set_insert(src_mac)) {
        s_stats.unique_macs = s_mac_count;
        int64_t now = esp_timer_get_time();
        sniffer_event_msg_t new_dev_msg = {
            .type = SNIFFER_EVT_NEW_DEVICE,
            .rssi = (int8_t)rssi,
            .channel = (uint8_t)chan,
            .timestamp_s = now / 1000000LL,
            .reason = 0,
            .ssid = {0},
        };
        memcpy(new_dev_msg.mac, src_mac, 6);
        if (xQueueSend(s_event_queue, &new_dev_msg, 0) != pdTRUE) {
            s_stats.dropped_events++;
        }
    }

    sniffer_event_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    memcpy(msg.mac, src_mac, 6);
    msg.rssi = (int8_t)rssi;
    msg.channel = (uint8_t)chan;

    switch (fc_subtype) {
    case WLAN_FC_STYPE_BEACON:
        msg.type = SNIFFER_EVT_BEACON;
        extract_ssid(body, body_len, 12, msg.ssid, sizeof(msg.ssid));
        break;

    case WLAN_FC_STYPE_PROBE_REQ:
        msg.type = SNIFFER_EVT_PROBE_REQ;
        extract_ssid(body, body_len, 0, msg.ssid, sizeof(msg.ssid));
        break;

    case WLAN_FC_STYPE_PROBE_RESP:
        msg.type = SNIFFER_EVT_PROBE_RESP;
        extract_ssid(body, body_len, 12, msg.ssid, sizeof(msg.ssid));
        break;

    case WLAN_FC_STYPE_ASSOC_REQ:
        msg.type = SNIFFER_EVT_ASSOC_REQ;
        extract_ssid(body, body_len, 4, msg.ssid, sizeof(msg.ssid));
        break;

    case WLAN_FC_STYPE_ASSOC_RESP:
        msg.type = SNIFFER_EVT_ASSOC_RESP;
        break;

    case WLAN_FC_STYPE_DEAUTH:
        msg.type = SNIFFER_EVT_DEAUTH;
        if (body_len >= 2) {
            msg.reason = (uint16_t)(body[0] | (body[1] << 8));
        }
        break;

    default:
        return;
    }

    if (xQueueSend(s_event_queue, &msg, 0) != pdTRUE) {
        s_stats.dropped_events++;
    }
}





static void sniffer_uart_task(void *arg)
{
    (void)arg;
    sniffer_event_msg_t msg;
    TickType_t last_heartbeat = xTaskGetTickCount();
    const TickType_t heartbeat_interval = pdMS_TO_TICKS(HEARTBEAT_INTERVAL_MS);

    while (s_running) {
        if (xQueueReceive(s_event_queue, &msg, pdMS_TO_TICKS(200)) == pdTRUE) {
            switch (msg.type) {
            case SNIFFER_EVT_NEW_DEVICE:
                printf("EVT:NEW_DEVICE MAC:%02X:%02X:%02X:%02X:%02X:%02X RSSI:%d FIRST_SEEN:%" PRId64 "\n",
                       msg.mac[0], msg.mac[1], msg.mac[2],
                       msg.mac[3], msg.mac[4], msg.mac[5],
                       msg.rssi, msg.timestamp_s);
                break;
            case SNIFFER_EVT_BEACON:
                printf("EVT:BEACON MAC:%02X:%02X:%02X:%02X:%02X:%02X RSSI:%d CHAN:%d SSID:%s\n",
                       msg.mac[0], msg.mac[1], msg.mac[2],
                       msg.mac[3], msg.mac[4], msg.mac[5],
                       msg.rssi, msg.channel, msg.ssid);
                break;
            case SNIFFER_EVT_PROBE_REQ:
                printf("EVT:PROBE_REQ MAC:%02X:%02X:%02X:%02X:%02X:%02X RSSI:%d CHAN:%d SSID:%s\n",
                       msg.mac[0], msg.mac[1], msg.mac[2],
                       msg.mac[3], msg.mac[4], msg.mac[5],
                       msg.rssi, msg.channel, msg.ssid);
                break;
            case SNIFFER_EVT_PROBE_RESP:
                printf("EVT:PROBE_RESP MAC:%02X:%02X:%02X:%02X:%02X:%02X RSSI:%d CHAN:%d SSID:%s\n",
                       msg.mac[0], msg.mac[1], msg.mac[2],
                       msg.mac[3], msg.mac[4], msg.mac[5],
                       msg.rssi, msg.channel, msg.ssid);
                break;
            case SNIFFER_EVT_ASSOC_REQ:
                printf("EVT:ASSOC_REQ MAC:%02X:%02X:%02X:%02X:%02X:%02X RSSI:%d CHAN:%d SSID:%s\n",
                       msg.mac[0], msg.mac[1], msg.mac[2],
                       msg.mac[3], msg.mac[4], msg.mac[5],
                       msg.rssi, msg.channel, msg.ssid);
                break;
            case SNIFFER_EVT_ASSOC_RESP:
                printf("EVT:ASSOC_RESP MAC:%02X:%02X:%02X:%02X:%02X:%02X RSSI:%d CHAN:%d\n",
                       msg.mac[0], msg.mac[1], msg.mac[2],
                       msg.mac[3], msg.mac[4], msg.mac[5],
                       msg.rssi, msg.channel);
                break;
            case SNIFFER_EVT_DEAUTH:
                printf("EVT:DEAUTH MAC:%02X:%02X:%02X:%02X:%02X:%02X RSSI:%d CHAN:%d REASON:%u\n",
                       msg.mac[0], msg.mac[1], msg.mac[2],
                       msg.mac[3], msg.mac[4], msg.mac[5],
                       msg.rssi, msg.channel, msg.reason);
                break;
            }
        }

        TickType_t now = xTaskGetTickCount();
        if ((now - last_heartbeat) >= heartbeat_interval) {
            last_heartbeat = now;
            int64_t uptime_s = 0;
            if (s_stats.start_time_us > 0) {
                uptime_s = (esp_timer_get_time() - s_stats.start_time_us) / 1000000LL;
            }
            printf("EVT:HEARTBEAT SCANNING=%d UPTIME=%" PRId64 " FRAMES=%" PRIu32 " MACS=%" PRIu32 " DROPPED=%" PRIu32 "\n",
                   s_running ? 1 : 0, uptime_s, s_stats.total_frames, s_stats.unique_macs, s_stats.dropped_events);
        }
    }

    s_uart_task = NULL;
    vTaskDelete(NULL);
}





static void channel_hop_task(void *arg)
{
    (void)arg;
    uint8_t channel = 1;

    while (s_running) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_DWELL_MS));
        channel++;
        if (channel > CHANNEL_MAX) {
            channel = 1;
        }
    }

    s_hop_task = NULL;
    vTaskDelete(NULL);
}





esp_err_t wifi_sniffer_init(void)
{
    if (s_initialised) {
        return ESP_OK;
    }

    if (s_event_queue == NULL) {
        s_event_queue = xQueueCreate(SNIFFER_QUEUE_SIZE, sizeof(sniffer_event_msg_t));
        if (s_event_queue == NULL) {
            ESP_LOGE(TAG, "Failed to create sniffer event queue");
            return ESP_ERR_NO_MEM;
        }
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Wi-Fi initialised in STA mode (no connection)");
    s_initialised = true;
    return ESP_OK;
}

esp_err_t wifi_sniffer_start(void)
{
    if (!s_initialised) {
        ESP_LOGE(TAG, "Call wifi_sniffer_init() first");
        return ESP_ERR_INVALID_STATE;
    }
    if (s_running) {
        ESP_LOGW(TAG, "Already scanning");
        return ESP_ERR_INVALID_STATE;
    }


    mac_set_clear();
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.start_time_us = esp_timer_get_time();


    if (s_event_queue != NULL) {
        xQueueReset(s_event_queue);
    }

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    s_running = true;


    BaseType_t ret_uart = xTaskCreate(sniffer_uart_task, "sniffer_uart",
                                      UART_TASK_STACK, NULL, UART_TASK_PRIO, &s_uart_task);
    if (ret_uart != pdPASS) {
        ESP_LOGE(TAG, "Failed to create sniffer_uart task");
        esp_wifi_set_promiscuous(false);
        s_running = false;
        return ESP_FAIL;
    }


    BaseType_t ret_hop = xTaskCreate(channel_hop_task, "chan_hop",
                                     HOP_TASK_STACK, NULL, HOP_TASK_PRIO, &s_hop_task);
    if (ret_hop != pdPASS) {
        ESP_LOGE(TAG, "Failed to create channel_hop task");
        s_running = false;
        esp_wifi_set_promiscuous(false);
        return ESP_FAIL;
    }

    puts("WIFI_SNIFFER=started");
    return ESP_OK;
}

esp_err_t wifi_sniffer_stop(void)
{
    if (!s_running) {
        ESP_LOGW(TAG, "Not scanning");
        return ESP_ERR_INVALID_STATE;
    }

    s_running = false;


    while (s_hop_task != NULL || s_uart_task != NULL) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));

    puts("WIFI_SNIFFER=stopped");
    return ESP_OK;
}

bool wifi_sniffer_is_running(void)
{
    return s_running;
}

wifi_sniffer_stats_t wifi_sniffer_get_stats(void)
{
    return s_stats;
}
