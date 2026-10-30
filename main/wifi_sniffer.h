










#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif




typedef struct {
    uint32_t total_frames;
    uint32_t unique_macs;
    uint32_t dropped_events;
    int64_t  start_time_us;
} wifi_sniffer_stats_t;









esp_err_t wifi_sniffer_init(void);









esp_err_t wifi_sniffer_start(void);








esp_err_t wifi_sniffer_stop(void);




bool wifi_sniffer_is_running(void);




wifi_sniffer_stats_t wifi_sniffer_get_stats(void);

esp_err_t wifi_sniffer_raw_capture_start(uint8_t channel, const uint8_t bssid[6]);
esp_err_t wifi_sniffer_raw_capture_stop(void);
bool wifi_sniffer_raw_capture_is_running(void);

#ifdef __cplusplus
}
#endif
