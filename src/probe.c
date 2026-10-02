#include "tls_stream.h"
#include "lwip_transport.h"
#include "tap_network.h"
#include "FreeRTOS.h"
#include "task.h"
#include "mbedtls/version.h"
#include "lwip/init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *ca_path;
static int exit_status = 1;
static unsigned checks, failures;

static void check(bool passed, const char *label)
{
    ++checks;
    if (!passed) ++failures;
    printf("%s %s\n", passed ? "PASS" : "FAIL", label);
}

static void exchange(const char *label, const char *host, uint16_t port,
                     tls_status expected, uint32_t expected_flags,
                     bool clock_ready, bool entropy_ready)
{
    lwip_transport transport;
    int result = lwip_transport_init(&transport, ca_path);
    if (result) {
        check(false, "load trust anchor");
        lwip_transport_destroy(&transport);
        return;
    }
    transport.clock_ready = clock_ready;
    transport.entropy_ready = entropy_ready;
    tls_stream_port callbacks = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&callbacks);
    if (!stream) {
        check(false, "allocate stream");
        lwip_transport_destroy(&transport);
        return;
    }
    int64_t start = callbacks.now_ms(&transport);
    tls_status status = tls_stream_open(stream, host, port, 5000);
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    check(status == expected, label);
    if (expected_flags) check((diagnostic.verify_flags & expected_flags) != 0, "certificate rejection reason");
    if (status == TLS_OK) {
        static const uint8_t request[] = "GET /probe HTTP/1.1\r\nHost: tls.lab.test\r\nConnection: close\r\n\r\n";
        static const uint8_t expected_response[] = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nlwip-ok\n";
        size_t sent = 0, received = 0;
        while (sent < sizeof(request) - 1) {
            int count = tls_stream_write(stream, request + sent, sizeof(request) - 1 - sent);
            if (count <= 0) break;
            sent += (size_t)count;
        }
        uint8_t response[256];
        int count = -1;
        while (received < sizeof(response) &&
               (count = tls_stream_read(stream, response + received, sizeof(response) - received)) > 0) {
            received += (size_t)count;
        }
        check(sent == sizeof(request) - 1, "complete request written");
        check(received == sizeof(expected_response) - 1 &&
              memcmp(response, expected_response, received) == 0, "exact HTTP response bytes");
        check(count == 0 && tls_stream_status(stream) == TLS_OK, "authenticated orderly close");
    }
    printf("RESULT %s status=%d stage=%d code=%d verify=%lu elapsed_ms=%lld\n",
           label, status, diagnostic.stage, diagnostic.code,
           (unsigned long)diagnostic.verify_flags,
           (long long)(callbacks.now_ms(&transport) - start));
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "transport released");
    lwip_transport_destroy(&transport);
}

static void client_task(void *context)
{
    (void)context;
    tap_network_start();
    printf("FreeRTOS=%s lwIP=%s MbedTLS=%s\n", tskKERNEL_VERSION_NUMBER,
           LWIP_VERSION_STRING, MBEDTLS_VERSION_STRING);
    TickType_t start = xTaskGetTickCount();
    exchange("valid-chain", "tls.lab.test", 8443, TLS_OK, 0, true, true);
    exchange("wrong-host", "wrong.lab.test", 8443, TLS_ERROR, MBEDTLS_X509_BADCERT_CN_MISMATCH, true, true);
    exchange("recovery-after-host", "tls.lab.test", 8443, TLS_OK, 0, true, true);
    exchange("unknown-root", "tls.lab.test", 8444, TLS_ERROR, MBEDTLS_X509_BADCERT_NOT_TRUSTED, true, true);
    exchange("recovery-after-root", "tls.lab.test", 8443, TLS_OK, 0, true, true);
    exchange("missing-time", "tls.lab.test", 8443, TLS_TIME_UNAVAILABLE, 0, false, true);
    exchange("missing-entropy", "tls.lab.test", 8443, TLS_ERROR, 0, true, false);
    exchange("final-recovery", "tls.lab.test", 8443, TLS_OK, 0, true, true);
    uint32_t received, sent;
    tap_network_counts(&received, &sent);
    check(received > 0 && sent > 0, "traffic crossed lwIP TAP interface");
    check(xTaskGetTickCount() > start, "FreeRTOS ticks advanced");
    printf("SUMMARY checks=%u failures=%u rx=%lu tx=%lu ticks=%lu\n", checks, failures,
           (unsigned long)received, (unsigned long)sent,
           (unsigned long)(xTaskGetTickCount() - start));
    fflush(stdout);
    exit_status = failures ? 1 : 0;
    vTaskEndScheduler();
    abort();
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s TAP_INTERFACE CA_FILE\n", argv[0]);
        return 2;
    }
    ca_path = argv[2];
    if (tap_network_open(argv[1])) {
        perror("open private TAP interface");
        return 2;
    }
    if (xTaskCreate(client_task, "tls-client", 32768, NULL, 1, NULL) != pdPASS) {
        tap_network_close();
        return 2;
    }
    vTaskStartScheduler();
    tap_network_close();
    return exit_status;
}
