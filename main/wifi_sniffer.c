





















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
#define DATA_SAMPLE_INTERVAL_US 100000
#define RAW_FRAME_QUEUE_SIZE 8
#define RAW_FRAME_MAX_LEN 2352

static const char *TAG = "wifi_sniffer";





typedef enum {
    SNIFFER_EVT_BEACON,
    SNIFFER_EVT_PROBE_REQ,
    SNIFFER_EVT_PROBE_RESP,
    SNIFFER_EVT_ASSOC_REQ,
    SNIFFER_EVT_ASSOC_RESP,
    SNIFFER_EVT_DEAUTH,
    SNIFFER_EVT_DATA,
    SNIFFER_EVT_NEW_DEVICE,
} sniffer_evt_type_t;

typedef enum {
    SNIFFER_DIR_MANAGEMENT,
    SNIFFER_DIR_CLIENT_TO_AP,
    SNIFFER_DIR_AP_TO_CLIENT,
    SNIFFER_DIR_DIRECT,
    SNIFFER_DIR_WDS,
} sniffer_direction_t;

typedef struct {
    sniffer_evt_type_t type;
    uint8_t mac[6];
    uint8_t dst_mac[6];
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t channel;
    uint16_t reason;
    uint16_t status_code;
    uint16_t frame_len;
    uint16_t sequence;
    uint8_t subtype;
    uint8_t qos_tid;
    sniffer_direction_t direction;
    bool protected_frame;
    bool retry;
    bool power_save;
    int64_t timestamp_s;
    char ssid[33];
} sniffer_event_msg_t;

typedef struct {
    uint16_t length;
    int8_t rssi;
    uint8_t channel;
    uint8_t frame[RAW_FRAME_MAX_LEN];
} raw_frame_msg_t;





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
static QueueHandle_t         s_raw_ready_queue = NULL;
static QueueHandle_t         s_raw_free_queue = NULL;
static raw_frame_msg_t       s_raw_pool[RAW_FRAME_QUEUE_SIZE];
static volatile bool         s_raw_capture  = false;
static volatile bool         s_raw_frame_sending = false;
static uint8_t               s_raw_channel  = 0;
static uint8_t               s_raw_bssid[6] = {0};
static char                  s_raw_line[RAW_FRAME_MAX_LEN * 2 + 96];
static wifi_sniffer_stats_t  s_stats        = {0};





typedef struct __attribute__((packed)) {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} wifi_ieee80211_hdr_t;

static void format_mac(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

#define WLAN_FC_TYPE_MGMT        0x00
#define WLAN_FC_TYPE_DATA        0x02
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
            for (size_t i = 0; i < copy_len; i++) {
                uint8_t ch = tags[offset + 2 + i];
                out_ssid[i] = (ch >= 0x20 && ch <= 0x7E) ? (char)ch : '?';
            }
            out_ssid[copy_len] = '\0';
            return;
        }
        offset += 2 + tag_len;
    }
}

static uint8_t extract_advertised_channel(const uint8_t *body, int body_len, int fixed_len)
{
    if (body_len <= fixed_len) {
        return 0;
    }
    const uint8_t *tags = body + fixed_len;
    int tags_len = body_len - fixed_len;
    int offset = 0;
    while (offset + 2 <= tags_len) {
        const uint8_t tag_id = tags[offset];
        const uint8_t tag_len = tags[offset + 1];
        if (offset + 2 + tag_len > tags_len) {
            return 0;
        }
        if ((tag_id == 3 || tag_id == 61) && tag_len >= 1) {
            return tags[offset + 2];
        }
        offset += 2 + tag_len;
    }
    return 0;
}





static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if ((type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) || s_event_queue == NULL) {
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

    if ((type == WIFI_PKT_MGMT && fc_type != WLAN_FC_TYPE_MGMT) ||
        (type == WIFI_PKT_DATA && fc_type != WLAN_FC_TYPE_DATA)) {
        return;
    }

    s_stats.total_frames++;

    const bool is_data = type == WIFI_PKT_DATA;
    const bool to_ds = (hdr->frame_ctrl & 0x0100) != 0;
    const bool from_ds = (hdr->frame_ctrl & 0x0200) != 0;
    const uint8_t *src_mac = hdr->addr2;
    const uint8_t *dst_mac = hdr->addr1;
    const uint8_t *bssid = hdr->addr3;
    sniffer_direction_t direction = SNIFFER_DIR_MANAGEMENT;

    if (is_data) {
        if (to_ds && !from_ds) {
            dst_mac = hdr->addr3;
            bssid = hdr->addr1;
            direction = SNIFFER_DIR_CLIENT_TO_AP;
        } else if (!to_ds && from_ds) {
            src_mac = hdr->addr3;
            bssid = hdr->addr2;
            direction = SNIFFER_DIR_AP_TO_CLIENT;
        } else if (to_ds && from_ds) {
            bssid = NULL;
            direction = SNIFFER_DIR_WDS;
        } else {
            direction = SNIFFER_DIR_DIRECT;
        }
    }
    int rssi  = rx->rssi;
    int chan  = rx->channel;

    if (s_raw_capture && chan == s_raw_channel && bssid != NULL &&
        memcmp(bssid, s_raw_bssid, 6) == 0) {
        if (len > RAW_FRAME_MAX_LEN) {
            s_stats.dropped_events++;
            return;
        }
        uint8_t slot = 0;
        if (s_raw_free_queue == NULL || s_raw_ready_queue == NULL ||
            xQueueReceive(s_raw_free_queue, &slot, 0) != pdTRUE) {
            s_stats.dropped_events++;
            return;
        }
        raw_frame_msg_t *raw_msg = &s_raw_pool[slot];
        raw_msg->length = (uint16_t)len;
        raw_msg->rssi = (int8_t)rssi;
        raw_msg->channel = (uint8_t)chan;
        memcpy(raw_msg->frame, payload, (size_t)len);
        if (xQueueSend(s_raw_ready_queue, &slot, 0) != pdTRUE) {
            (void)xQueueSend(s_raw_free_queue, &slot, 0);
            s_stats.dropped_events++;
        }
        return;
    }

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
        memcpy(new_dev_msg.dst_mac, dst_mac, 6);
        if (bssid != NULL) {
            memcpy(new_dev_msg.bssid, bssid, 6);
        }
        if (xQueueSend(s_event_queue, &new_dev_msg, 0) != pdTRUE) {
            s_stats.dropped_events++;
        }
    }

    sniffer_event_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    memcpy(msg.mac, src_mac, 6);
    memcpy(msg.dst_mac, dst_mac, 6);
    if (bssid != NULL) {
        memcpy(msg.bssid, bssid, 6);
    }
    msg.rssi = (int8_t)rssi;
    msg.channel = (uint8_t)chan;
    msg.frame_len = (uint16_t)len;
    msg.sequence = (uint16_t)(hdr->seq_ctrl >> 4);
    msg.subtype = fc_subtype;
    msg.qos_tid = 255;
    msg.direction = direction;
    msg.protected_frame = (hdr->frame_ctrl & 0x4000) != 0;
    msg.retry = (hdr->frame_ctrl & 0x0800) != 0;
    msg.power_save = (hdr->frame_ctrl & 0x1000) != 0;

    if (is_data) {
        if ((fc_subtype & 0x08) != 0) {
            const int qos_offset = (to_ds && from_ds) ? 30 : 24;
            if (len >= qos_offset + 2) {
                msg.qos_tid = payload[qos_offset] & 0x0F;
            }
        }
        const int64_t now_us = esp_timer_get_time();
        static int64_t last_data_sample_us;
        if (now_us - last_data_sample_us < DATA_SAMPLE_INTERVAL_US) {
            return;
        }
        last_data_sample_us = now_us;
        msg.type = SNIFFER_EVT_DATA;
        if (xQueueSend(s_event_queue, &msg, 0) != pdTRUE) {
            s_stats.dropped_events++;
        }
        return;
    }

    switch (fc_subtype) {
    case WLAN_FC_STYPE_BEACON:
        msg.type = SNIFFER_EVT_BEACON;
        extract_ssid(body, body_len, 12, msg.ssid, sizeof(msg.ssid));
        {
            const uint8_t ap_channel = extract_advertised_channel(body, body_len, 12);
            if (ap_channel >= 1 && ap_channel <= CHANNEL_MAX) {
                msg.channel = ap_channel;
            }
        }
        break;

    case WLAN_FC_STYPE_PROBE_REQ:
        msg.type = SNIFFER_EVT_PROBE_REQ;
        extract_ssid(body, body_len, 0, msg.ssid, sizeof(msg.ssid));
        break;

    case WLAN_FC_STYPE_PROBE_RESP:
        msg.type = SNIFFER_EVT_PROBE_RESP;
        extract_ssid(body, body_len, 12, msg.ssid, sizeof(msg.ssid));
        {
            const uint8_t ap_channel = extract_advertised_channel(body, body_len, 12);
            if (ap_channel >= 1 && ap_channel <= CHANNEL_MAX) {
                msg.channel = ap_channel;
            }
        }
        break;

    case WLAN_FC_STYPE_ASSOC_REQ:
        msg.type = SNIFFER_EVT_ASSOC_REQ;
        extract_ssid(body, body_len, 4, msg.ssid, sizeof(msg.ssid));
        break;

    case WLAN_FC_STYPE_ASSOC_RESP:
        msg.type = SNIFFER_EVT_ASSOC_RESP;
        if (body_len >= 4) {
            msg.status_code = (uint16_t)(body[2] | (body[3] << 8));
        }
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
    char src_text[18];
    char dst_text[18];
    char bssid_text[18];
    TickType_t last_heartbeat = xTaskGetTickCount();
    const TickType_t heartbeat_interval = pdMS_TO_TICKS(HEARTBEAT_INTERVAL_MS);

    while (s_running) {
        uint8_t raw_slot = 0;
        s_raw_frame_sending = true;
        const bool have_raw = s_raw_ready_queue != NULL &&
                              xQueueReceive(s_raw_ready_queue, &raw_slot, 0) == pdTRUE;
        if (have_raw) {
            raw_frame_msg_t *raw_msg = &s_raw_pool[raw_slot];
            int offset = snprintf(s_raw_line, sizeof(s_raw_line),
                                  "EVT:RAW CHAN=%u RSSI=%d LEN=%u HEX=",
                                  raw_msg->channel, raw_msg->rssi, raw_msg->length);
            static const char hex[] = "0123456789ABCDEF";
            for (uint16_t i = 0; i < raw_msg->length && offset + 2 < (int)sizeof(s_raw_line); i++) {
                s_raw_line[offset++] = hex[raw_msg->frame[i] >> 4];
                s_raw_line[offset++] = hex[raw_msg->frame[i] & 0x0F];
            }
            s_raw_line[offset++] = '\r';
            s_raw_line[offset++] = '\n';
            fwrite(s_raw_line, 1, (size_t)offset, stdout);
            (void)xQueueSend(s_raw_free_queue, &raw_slot, 0);
        }
        s_raw_frame_sending = false;
        if (!have_raw && xQueueReceive(s_event_queue, &msg, pdMS_TO_TICKS(100)) == pdTRUE) {
            format_mac(msg.mac, src_text);
            format_mac(msg.dst_mac, dst_text);
            format_mac(msg.bssid, bssid_text);
            switch (msg.type) {
            case SNIFFER_EVT_NEW_DEVICE:
                printf("EVT:NEW_DEVICE MAC:%02X:%02X:%02X:%02X:%02X:%02X RSSI:%d FIRST_SEEN:%" PRId64 "\n",
                       msg.mac[0], msg.mac[1], msg.mac[2],
                       msg.mac[3], msg.mac[4], msg.mac[5],
                       msg.rssi, msg.timestamp_s);
                break;
            case SNIFFER_EVT_BEACON:
                printf("EVT:BEACON MAC:%s SRC=%s DST=%s BSSID=%s RSSI=%d CHAN=%d SSID:%s\n",
                       src_text, src_text, dst_text, bssid_text, msg.rssi, msg.channel, msg.ssid);
                break;
            case SNIFFER_EVT_PROBE_REQ:
                printf("EVT:PROBE_REQ MAC:%s SRC=%s DST=%s BSSID=%s RSSI=%d CHAN=%d SSID:%s\n",
                       src_text, src_text, dst_text, bssid_text, msg.rssi, msg.channel, msg.ssid);
                break;
            case SNIFFER_EVT_PROBE_RESP:
                printf("EVT:PROBE_RESP MAC:%s SRC=%s DST=%s BSSID=%s RSSI=%d CHAN=%d SSID:%s\n",
                       src_text, src_text, dst_text, bssid_text, msg.rssi, msg.channel, msg.ssid);
                break;
            case SNIFFER_EVT_ASSOC_REQ:
                printf("EVT:ASSOC_REQ MAC:%s SRC=%s DST=%s BSSID=%s RSSI=%d CHAN=%d SSID:%s\n",
                       src_text, src_text, dst_text, bssid_text, msg.rssi, msg.channel, msg.ssid);
                break;
            case SNIFFER_EVT_ASSOC_RESP:
                printf("EVT:ASSOC_RESP MAC:%s SRC=%s DST=%s BSSID=%s STATUS=%u RSSI=%d CHAN=%d\n",
                       src_text, src_text, dst_text, bssid_text, msg.status_code, msg.rssi, msg.channel);
                break;
            case SNIFFER_EVT_DEAUTH:
                printf("EVT:DEAUTH MAC:%s SRC=%s DST=%s BSSID=%s RSSI=%d CHAN:%d REASON=%u\n",
                       src_text, src_text, dst_text, bssid_text, msg.rssi, msg.channel, msg.reason);
                break;
            case SNIFFER_EVT_DATA: {
                const char *dir = "DIRECT";
                if (msg.direction == SNIFFER_DIR_CLIENT_TO_AP) dir = "CLIENT_TO_AP";
                else if (msg.direction == SNIFFER_DIR_AP_TO_CLIENT) dir = "AP_TO_CLIENT";
                else if (msg.direction == SNIFFER_DIR_WDS) dir = "WDS_HOP";
                printf("EVT:DATA MAC:%s SRC=%s DST=%s BSSID=%s DIR=%s LEN=%u SUBTYPE=%u TID=%u PROTECTED=%d RETRY=%d PM=%d SEQ=%u RSSI=%d CHAN=%d\n",
                       src_text, src_text, dst_text, bssid_text, dir, msg.frame_len, msg.subtype, msg.qos_tid,
                       msg.protected_frame ? 1 : 0, msg.retry ? 1 : 0,
                       msg.power_save ? 1 : 0, msg.sequence, msg.rssi, msg.channel);
                break;
            }
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
        if (s_raw_capture) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
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
    if (s_raw_ready_queue == NULL) {
        s_raw_ready_queue = xQueueCreate(RAW_FRAME_QUEUE_SIZE, sizeof(uint8_t));
        s_raw_free_queue = xQueueCreate(RAW_FRAME_QUEUE_SIZE, sizeof(uint8_t));
        if (s_raw_ready_queue == NULL || s_raw_free_queue == NULL) {
            ESP_LOGE(TAG, "Failed to create raw frame queue");
            return ESP_ERR_NO_MEM;
        }
        for (uint8_t i = 0; i < RAW_FRAME_QUEUE_SIZE; i++) {
            (void)xQueueSend(s_raw_free_queue, &i, 0);
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
    if (s_raw_ready_queue != NULL && s_raw_free_queue != NULL) {
        xQueueReset(s_raw_ready_queue);
        xQueueReset(s_raw_free_queue);
        for (uint8_t i = 0; i < RAW_FRAME_QUEUE_SIZE; i++) {
            (void)xQueueSend(s_raw_free_queue, &i, 0);
        }
    }

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
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

    s_raw_capture = false;
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

esp_err_t wifi_sniffer_raw_capture_start(uint8_t channel, const uint8_t bssid[6])
{
    if (!s_running || bssid == NULL || channel < 1 || channel > CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_raw_capture) {
        return ESP_ERR_INVALID_STATE;
    }
    memcpy(s_raw_bssid, bssid, sizeof(s_raw_bssid));
    s_raw_channel = channel;
    esp_err_t result = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (result != ESP_OK) {
        return result;
    }
    s_raw_capture = true;
    printf("STATUS: Raw capture started on channel %u for %02X:%02X:%02X:%02X:%02X:%02X\n",
           channel, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    return ESP_OK;
}

esp_err_t wifi_sniffer_raw_capture_stop(void)
{
    if (!s_raw_capture) {
        return ESP_ERR_INVALID_STATE;
    }
    s_raw_capture = false;
    uint8_t idle_checks = 0;
    while (idle_checks < 5) {
        const bool queue_empty = s_raw_ready_queue == NULL ||
                                 uxQueueMessagesWaiting(s_raw_ready_queue) == 0;
        if (queue_empty && !s_raw_frame_sending) {
            idle_checks++;
        } else {
            idle_checks = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    puts("STATUS: Raw capture stopped");
    return ESP_OK;
}

bool wifi_sniffer_raw_capture_is_running(void)
{
    return s_raw_capture;
}

wifi_sniffer_stats_t wifi_sniffer_get_stats(void)
{
    return s_stats;
}
