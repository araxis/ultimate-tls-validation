#include "tls_stream.h"
#include "lwip_transport.h"
#include "lwip_dns.h"
#include "pressure.h"
#include "connect.h"
#include "sessions.h"
#include "security.h"
#include "tap_network.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "mbedtls/version.h"
#include "lwip/init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *ca_path;
static int exit_status = 1;
static unsigned checks, failures;
static bool faults;
static bool pressure;
static bool connections;
static bool sessions;
static bool security;
static const uint8_t request_bytes[] = "GET /probe HTTP/1.1\r\nHost: tls.lab.test\r\nConnection: close\r\n\r\n";

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
        static const uint8_t expected_response[] = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nlwip-ok\n";
        size_t sent = 0, received = 0;
        while (sent < sizeof(request_bytes) - 1) {
            int count = tls_stream_write(stream, request_bytes + sent, sizeof(request_bytes) - 1 - sent);
            if (count <= 0) break;
            sent += (size_t)count;
        }
        uint8_t response[256];
        int count = -1;
        while (received < sizeof(response) &&
               (count = tls_stream_read(stream, response + received, sizeof(response) - received)) > 0) {
            received += (size_t)count;
        }
        check(sent == sizeof(request_bytes) - 1, "complete request written");
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

struct cancel_request {
    lwip_transport *transport;
    SemaphoreHandle_t completed;
};

static void cancel_task(void *context)
{
    struct cancel_request *request = context;
    vTaskDelay(pdMS_TO_TICKS(50));
    lwip_transport_cancel(request->transport);
    xSemaphoreGive(request->completed);
    vTaskDelete(NULL);
}

static void start_cancellation(struct cancel_request *request)
{
    request->completed = xSemaphoreCreateBinary();
    configASSERT(request->completed);
    configASSERT(xTaskCreate(cancel_task, "cancel", 4096, request, 2, NULL) == pdPASS);
}

static void join_cancellation(struct cancel_request *request)
{
    if (request->completed) {
        configASSERT(xSemaphoreTake(request->completed, pdMS_TO_TICKS(1000)) == pdTRUE);
        vSemaphoreDelete(request->completed);
    }
}

static void open_fault(const char *label, const char *host, uint16_t port,
                       bool cancel, tls_stage expected_stage)
{
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca_path) == 0);
    tls_stream_port callbacks = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&callbacks);
    configASSERT(stream);
    struct cancel_request request = {&transport, NULL};
    if (cancel) start_cancellation(&request);
    int64_t start = callbacks.now_ms(&transport);
    tls_status status = tls_stream_open(stream, host, port, cancel ? 5000 : 100);
    int64_t elapsed = callbacks.now_ms(&transport) - start;
    check(status == (cancel ? TLS_CANCELLED : TLS_TIMEOUT), label);
    /* 250 ms scheduling allowance is a test tolerance, not a larger deadline. */
    check(elapsed >= 0 && elapsed <= (cancel ? 300 : 350), "bounded open wait");
    check(tls_stream_diagnostic(stream).stage == expected_stage, "expected fault phase");
    printf("RESULT %s status=%d elapsed_ms=%lld\n", label, status, (long long)elapsed);
    join_cancellation(&request);
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "fault transport released");
    lwip_transport_destroy(&transport);
}

static void read_fault(const char *label, bool cancel)
{
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca_path) == 0);
    tls_stream_port callbacks = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&callbacks);
    configASSERT(stream);
    int64_t start = callbacks.now_ms(&transport);
    check(tls_stream_open(stream, "tls.lab.test", 8446, cancel ? 5000 : 500) == TLS_OK,
          "read fault starts after verified handshake");
    size_t sent = 0;
    while (sent < sizeof(request_bytes) - 1) {
        int count = tls_stream_write(stream, request_bytes + sent, sizeof(request_bytes) - 1 - sent);
        if (count <= 0) break;
        sent += (size_t)count;
    }
    check(sent == sizeof(request_bytes) - 1, "read fault request complete");
    struct cancel_request request = {&transport, NULL};
    if (cancel) start_cancellation(&request);
    uint8_t byte;
    int result = tls_stream_read(stream, &byte, sizeof(byte));
    int64_t elapsed = callbacks.now_ms(&transport) - start;
    tls_status status = tls_stream_status(stream);
    check(result < 0 && status == (cancel ? TLS_CANCELLED : TLS_TIMEOUT), label);
    check(elapsed >= 0 && elapsed <= (cancel ? 350 : 750), "bounded read wait");
    check(tls_stream_diagnostic(stream).stage == TLS_STAGE_READ, "expected read fault phase");
    printf("RESULT %s status=%d elapsed_ms=%lld\n", label, status, (long long)elapsed);
    join_cancellation(&request);
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "read fault transport released");
    lwip_transport_destroy(&transport);
}

static void client_task(void *context)
{
    (void)context;
    tap_network_start();
    printf("FreeRTOS=%s lwIP=%s MbedTLS=%s\n", tskKERNEL_VERSION_NUMBER,
           LWIP_VERSION_STRING, MBEDTLS_VERSION_STRING);
    TickType_t start = xTaskGetTickCount();
    if (security) {
        struct security_results result = security_tests(ca_path);
        checks += result.checks;
        failures += result.failures;
        exchange("security-recovery", "tls.lab.test", 8443, TLS_OK, 0, true, true);
    } else if (sessions) {
        struct session_results result = session_tests(ca_path);
        checks += result.checks;
        failures += result.failures;
        exchange("sessions-recovery", "tls.lab.test", 8443, TLS_OK, 0, true, true);
    } else if (connections) {
        struct connect_results result = connect_tests(ca_path);
        checks += result.checks;
        failures += result.failures;
        exchange("connect-recovery", "tls.lab.test", 8443, TLS_OK, 0, true, true);
    } else if (pressure) {
        struct pressure_results result = pressure_tests(ca_path);
        checks += result.checks;
        failures += result.failures;
        exchange("pressure-recovery", "tls.lab.test", 8443, TLS_OK, 0, true, true);
    } else if (faults) {
        open_fault("dns-timeout", "silent.lab.test", 8443, false, TLS_STAGE_TCP_OPEN);
        open_fault("dns-cancel", "cancel.lab.test", 8443, true, TLS_STAGE_TCP_OPEN);
        open_fault("dns-late-reply", "late.lab.test", 8443, false, TLS_STAGE_TCP_OPEN);
        /* Give late callbacks time to run after their caller has been destroyed. */
        vTaskDelay(pdMS_TO_TICKS(3000));
        check(lwip_dns_pending() == 0, "abandoned DNS callbacks released all slots");
        open_fault("handshake-timeout", "tls.lab.test", 8445, false, TLS_STAGE_HANDSHAKE);
        open_fault("handshake-cancel", "tls.lab.test", 8445, true, TLS_STAGE_HANDSHAKE);
        read_fault("read-timeout", false);
        read_fault("read-cancel", true);
        exchange("dns-recovery", "tls.lab.test", 8443, TLS_OK, 0, true, true);
    } else {
        exchange("valid-chain", "tls.lab.test", 8443, TLS_OK, 0, true, true);
        exchange("wrong-host", "wrong.lab.test", 8443, TLS_ERROR, MBEDTLS_X509_BADCERT_CN_MISMATCH, true, true);
        exchange("recovery-after-host", "tls.lab.test", 8443, TLS_OK, 0, true, true);
        exchange("unknown-root", "tls.lab.test", 8444, TLS_ERROR, MBEDTLS_X509_BADCERT_NOT_TRUSTED, true, true);
        exchange("recovery-after-root", "tls.lab.test", 8443, TLS_OK, 0, true, true);
        exchange("missing-time", "tls.lab.test", 8443, TLS_TIME_UNAVAILABLE, 0, false, true);
        exchange("missing-entropy", "tls.lab.test", 8443, TLS_ERROR, 0, true, false);
        exchange("final-recovery", "tls.lab.test", 8443, TLS_OK, 0, true, true);
    }
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
    if (argc != 3 && !(argc == 4 &&
        (strcmp(argv[3], "--faults") == 0 || strcmp(argv[3], "--pressure") == 0 ||
         strcmp(argv[3], "--connections") == 0 || strcmp(argv[3], "--sessions") == 0 ||
         strcmp(argv[3], "--security") == 0))) {
        fprintf(stderr, "Usage: %s TAP_INTERFACE CA_FILE [--faults|--pressure|--connections|--sessions|--security]\n", argv[0]);
        return 2;
    }
    ca_path = argv[2];
    faults = argc == 4 && strcmp(argv[3], "--faults") == 0;
    pressure = argc == 4 && strcmp(argv[3], "--pressure") == 0;
    connections = argc == 4 && strcmp(argv[3], "--connections") == 0;
    sessions = argc == 4 && strcmp(argv[3], "--sessions") == 0;
    security = argc == 4 && strcmp(argv[3], "--security") == 0;
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
