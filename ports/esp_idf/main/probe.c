#include "transport.h"
#include "fixture.h"
#include "authentication.h"
#include "timing.h"
#include "socket_waits.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "lwip/init.h"
#include "lwip/ip4_addr.h"
#include "mbedtls/version.h"
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

static EventGroupHandle_t events;
static unsigned checks, failures;

static void check(bool passed, const char *label)
{
    ++checks;
    if (!passed) ++failures;
    printf("%s %s\n", passed ? "PASS" : "FAIL", label);
}

static void got_ip(void *context, esp_event_base_t base, int32_t id, void *data)
{
    (void)context;
    (void)base;
    (void)id;
    (void)data;
    xEventGroupSetBits(events, 1);
}

void app_main(void)
{
    printf("PORT esp32s3 IDF=%s FreeRTOS=%s lwIP=%s MbedTLS=%s run=%s\n",
           esp_get_idf_version(), tskKERNEL_VERSION_NUMBER, LWIP_VERSION_STRING,
           MBEDTLS_VERSION_STRING, LAB_RUN_ID);
    TickType_t start = xTaskGetTickCount();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    events = xEventGroupCreate();
    configASSERT(events);
    esp_netif_config_t net_config = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *netif = esp_netif_new(&net_config);
    configASSERT(netif);
    ESP_ERROR_CHECK(esp_netif_dhcpc_stop(netif));
    esp_netif_ip_info_t ip = {0};
    IP4_ADDR(&ip.ip, 192, 0, 2, 2);
    IP4_ADDR(&ip.netmask, 255, 255, 255, 252);
    /* No gateway: this guest only talks to the private fixture subnet. */
    ESP_ERROR_CHECK(esp_netif_set_ip_info(netif, &ip));
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.reset_gpio_num = -1;
    phy_config.autonego_timeout_ms = 100;
    esp_eth_mac_t *mac = esp_eth_mac_new_openeth(&mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_dp83848(&phy_config);
    configASSERT(mac && phy);
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t driver;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &driver));
    uint8_t address[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    ESP_ERROR_CHECK(esp_eth_ioctl(driver, ETH_CMD_S_MAC_ADDR, address));
    esp_eth_netif_glue_handle_t glue = esp_eth_new_netif_glue(driver);
    configASSERT(glue);
    ESP_ERROR_CHECK(esp_netif_attach(netif, glue));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, got_ip, NULL));
    ESP_ERROR_CHECK(esp_eth_start(driver));
    bool connected = (xEventGroupWaitBits(events, 1, pdFALSE, pdTRUE, pdMS_TO_TICKS(5000)) & 1) != 0;
    check(connected, "guest Ethernet ready");

    struct timeval utc = {.tv_sec = LAB_UTC_SECONDS, .tv_usec = 0};
    bool clock_ready = settimeofday(&utc, NULL) == 0;
    check(clock_ready, "fixture UTC installed");
#if defined(LAB_SOCKET_WAITS)
    socket_waits_probe(connected && clock_ready, check);
#elif defined(LAB_TIMING)
    timing_probe(connected && clock_ready, check);
#elif defined(LAB_AUTHENTICATION)
    authentication_probe(connected && clock_ready, check);
#else
    idf_transport transport;
    int loaded = idf_transport_init(&transport, lab_root, sizeof(lab_root));
    check(loaded == 0, "fixture trust anchor loaded");
    transport.clock_ready = clock_ready;
    tls_stream_port port = idf_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    check(stream != NULL, "stream allocated");
    tls_status status = TLS_INVALID_ARGUMENT;
    if (connected && !loaded && stream) status = tls_stream_open(stream, "192.0.2.1", 8443, 15000);
    check(status == TLS_OK && tls_stream_diagnostic(stream).verify_flags == 0, "authenticated target exchange");
    static const uint8_t request[] = "GET /probe HTTP/1.1\r\nHost: tls.lab.test\r\nConnection: close\r\n\r\n";
    static const uint8_t expected[] = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nlwip-ok\n";
    size_t sent = 0, received = 0;
    uint8_t response[256];
    int count = -1;
    if (status == TLS_OK) {
        while (sent < sizeof(request) - 1) {
            count = tls_stream_write(stream, request + sent, sizeof(request) - 1 - sent);
            if (count <= 0) break;
            sent += (size_t)count;
        }
        while (received < sizeof(response) &&
               (count = tls_stream_read(stream, response + received, sizeof(response) - received)) > 0)
            received += (size_t)count;
    }
    check(sent == sizeof(request) - 1, "complete request written");
    check(received == sizeof(expected) - 1 && memcmp(response, expected, received) == 0,
          "exact response bytes");
    check(count == 0 && tls_stream_status(stream) == TLS_OK, "authenticated EOF");
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    printf("RESULT exchange status=%d stage=%d code=%d verify=%lu sent=%zu received=%zu\n",
           diagnostic.status, diagnostic.stage, diagnostic.code,
           (unsigned long)diagnostic.verify_flags, sent, received);
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "socket released");
    idf_transport_destroy(&transport);
#endif
    ESP_ERROR_CHECK(esp_eth_stop(driver));
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_ETH_GOT_IP, got_ip));
    ESP_ERROR_CHECK(esp_eth_del_netif_glue(glue));
    ESP_ERROR_CHECK(esp_eth_driver_uninstall(driver));
    ESP_ERROR_CHECK(phy->del(phy));
    ESP_ERROR_CHECK(mac->del(mac));
    esp_netif_destroy(netif);
    vEventGroupDelete(events);
    check(xTaskGetTickCount() > start, "guest scheduler advanced");
    printf("SUMMARY checks=%u failures=%u ticks=%lu run=%s\n", checks, failures,
           (unsigned long)(xTaskGetTickCount() - start), LAB_RUN_ID);
    fflush(stdout);
}
