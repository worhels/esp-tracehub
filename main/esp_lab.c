#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/uart.h"
#include "driver/usb_serial_jtag.h"
#include "esp_flash.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "wifi_sniffer.h"

typedef enum { IDLE, PASSED, HALTED } lab_state_t;
static lab_state_t state = IDLE;
static uint32_t required_mib = 16;
static bool usb_step = false;

static bool parse_mac_address(const char *text, uint8_t mac[6])
{
    unsigned int octets[6];
    char trailing;
    if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c",
               &octets[0], &octets[1], &octets[2],
               &octets[3], &octets[4], &octets[5], &trailing) != 6) {
        return false;
    }
    for (size_t i = 0; i < 6; i++) {
        if (octets[i] > 0xFF) {
            return false;
        }
        mac[i] = (uint8_t)octets[i];
    }
    return true;
}

static void print_status(void)
{
    const char *names[] = {"IDLE", "PASSED", "HALTED"};
    printf("STATE=%s STEP=%s REQUIRED_MIB=%" PRIu32 " FREE_HEAP=%" PRIu32 "\n",
           names[state], state == IDLE ? "none" : (usb_step ? "usb-host" : "flash-size"),
           required_mib, esp_get_free_heap_size());
}

static void check_flash(void)
{
    uint32_t bytes = 0;
    printf("STEP=flash-size REQUIRED_MIB=%" PRIu32 "\n", required_mib);
    const esp_err_t result = esp_flash_get_size(NULL, &bytes);
    if (result != ESP_OK) {
        state = HALTED;
        printf("FALSE ERROR=%s STATE=HALTED; waiting for retry or cancel\n", esp_err_to_name(result));
        return;
    }
    printf("OBSERVED_FLASH_BYTES=%" PRIu32 "\n", bytes);
    if (bytes < required_mib * 1024U * 1024U) {
        state = HALTED;
        puts("FALSE ERROR=flash_smaller_than_required STATE=HALTED; waiting for retry or cancel");
        return;
    }
    state = PASSED;
    puts("TRUE STATE=PASSED");
}

static void check_usb(void)
{
    puts("STEP=usb-host INTERFACE=native-usb-serial-jtag");
    if (usb_serial_jtag_is_connected()) {
        state = PASSED;
        puts("TRUE STATE=PASSED USB_HOST_ACTIVITY=observed HOST_IDENTITY=unknown");
    } else {
        state = HALTED;
        puts("FALSE STATE=HALTED ERROR=no_usb_host_activity; waiting for retry or cancel");
    }
}

static void handle_command(const char *command)
{
    if (strcmp(command, "help") == 0) {
        puts("help | status | usb-check | flash-check <1..128 MiB> | retry | cancel");
        puts("wifi-scan | wifi-stop | wifi-status");
        puts("wifi-raw-start <channel 1..13> <BSSID> | wifi-raw-stop");
        puts("FALSE latches HALTED. No automatic retry. cancel returns to IDLE.");
    } else if (strcmp(command, "status") == 0) {
        print_status();
    } else if (strcmp(command, "cancel") == 0) {
        state = IDLE;
        puts("CANCELLED STATE=IDLE");
    } else if (strcmp(command, "retry") == 0) {
        if (state != HALTED) {
            puts("ERROR=no_failed_step");
        } else if (usb_step) {
            check_usb();
        } else {
            check_flash();
        }
    } else if (strcmp(command, "usb-check") == 0) {
        if (state == HALTED) {
            puts("BLOCKED STATE=HALTED; use retry or cancel");
        } else {
            usb_step = true;
            check_usb();
        }
    } else if (strncmp(command, "flash-check ", 12) == 0) {
        if (state == HALTED) {
            puts("BLOCKED STATE=HALTED; use retry or cancel");
            return;
        }
        const char *argument = command + 12;
        char *end = NULL;
        errno = 0;
        const unsigned long value = strtoul(argument, &end, 10);
        if (errno != 0 || end == argument || *end != '\0' || value < 1 || value > 128) {
            puts("ERROR=expected_flash_size_1_to_128_MiB");
            return;
        }
        required_mib = (uint32_t)value;
        usb_step = false;
        check_flash();
    } else if (strcmp(command, "wifi-scan") == 0) {
        esp_err_t err = wifi_sniffer_start();
        if (err == ESP_ERR_INVALID_STATE && wifi_sniffer_is_running()) {
            puts("ERROR=already_scanning; use wifi-stop first");
        } else if (err != ESP_OK) {
            printf("ERROR=wifi_start_failed ERR=%s\n", esp_err_to_name(err));
        }
    } else if (strcmp(command, "wifi-stop") == 0) {
        esp_err_t err = wifi_sniffer_stop();
        if (err == ESP_ERR_INVALID_STATE) {
            puts("ERROR=not_scanning");
        } else if (err != ESP_OK) {
            printf("ERROR=wifi_stop_failed ERR=%s\n", esp_err_to_name(err));
        }
    } else if (strcmp(command, "wifi-status") == 0) {
        bool running = wifi_sniffer_is_running();
        wifi_sniffer_stats_t st = wifi_sniffer_get_stats();
        int64_t uptime_s = 0;
        if (running && st.start_time_us > 0) {
            uptime_s = (esp_timer_get_time() - st.start_time_us) / 1000000LL;
        }
        printf("WIFI_SNIFFER=%s\n", running ? "running" : "stopped");
        printf("EVT:STATS TOTAL_FRAMES=%" PRIu32 " UNIQUE_MACS=%" PRIu32 " DROPPED=%" PRIu32 " UPTIME=%" PRId64 "\n",
               st.total_frames, st.unique_macs, st.dropped_events, uptime_s);
    } else if (strncmp(command, "wifi-raw-start ", 15) == 0) {
        unsigned int channel = 0;
        char bssid_text[18] = {0};
        uint8_t bssid[6] = {0};
        if (sscanf(command + 15, "%u %17s", &channel, bssid_text) != 2 ||
            channel < 1 || channel > 13 || !parse_mac_address(bssid_text, bssid)) {
            puts("ERROR=expected_channel_1_to_13_and_bssid");
            return;
        }
        esp_err_t err = wifi_sniffer_raw_capture_start((uint8_t)channel, bssid);
        if (err != ESP_OK) {
            printf("ERROR=raw_capture_start_failed ERR=%s\n", esp_err_to_name(err));
        }
    } else if (strcmp(command, "wifi-raw-stop") == 0) {
        esp_err_t err = wifi_sniffer_raw_capture_stop();
        if (err != ESP_OK) {
            printf("ERROR=raw_capture_stop_failed ERR=%s\n", esp_err_to_name(err));
        }
    } else {
        puts("ERROR=unknown_command; use help");
    }
}

void app_main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    const esp_err_t result = uart_driver_install(UART_NUM_0, 2048, 0, 0, NULL, 0);
    if (result != ESP_OK) {
        printf("FALSE STEP=console-init ERROR=%s STATE=HALTED\n", esp_err_to_name(result));
        for (;;) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }

    esp_err_t wifi_err = wifi_sniffer_init();
    if (wifi_err != ESP_OK) {
        printf("WARNING wifi_sniffer_init failed: %s\n", esp_err_to_name(wifi_err));
    }

    puts("\nESP-LAB 0.2.0 READY; controller=ESP32-S3; console=UART0 115200 8N1");
    puts("Wi-Fi sniffer available. Type help and press Enter.");
    print_status();

    char line[128];
    size_t length = 0;
    bool discard = false;
    for (;;) {
        uint8_t byte = 0;
        const int count = uart_read_bytes(UART_NUM_0, &byte, 1, pdMS_TO_TICKS(100));
        if (count <= 0) {
            continue;
        }
        if (byte == '\r' || byte == '\n') {
            if (discard) {
                puts("ERROR=invalid_or_overlong_command; discarded");
            } else if (length > 0) {
                line[length] = '\0';
                handle_command(line);
            }
            length = 0;
            discard = false;
        } else if (byte == 8 || byte == 127) {
            if (!discard && length > 0) {
                --length;
            }
        } else if (!discard) {
            if (byte < 32 || byte > 126 || length >= sizeof(line) - 1) {
                discard = true;
            } else {
                line[length++] = (char)byte;
            }
        }
    }
}
