#include "resource_probe.h"
#include "allocation_meter.h"
#include "transport.h"
#include "lwip_dns.h"
#include "fixture.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcp_priv.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    SemaphoreHandle_t done;
    unsigned active, timewait, tcp_stack_free;
} network_snapshot;

static void capture_network(void *argument)
{
    network_snapshot *snapshot = argument;
    for (struct tcp_pcb *p = tcp_active_pcbs; p; p = p->next) ++snapshot->active;
    for (struct tcp_pcb *p = tcp_tw_pcbs; p; p = p->next) ++snapshot->timewait;
    snapshot->tcp_stack_free = uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t);
    xSemaphoreGive(snapshot->done);
}

static void report(unsigned attempt, const char *phase, SemaphoreHandle_t done,
                   void (*check)(bool, const char *))
{
    allocation_meter_pause(true);
    network_snapshot network = {.done = done};
    configASSERT(tcpip_callback(capture_network, &network) == ERR_OK);
    configASSERT(xSemaphoreTake(done, pdMS_TO_TICKS(1000)) == pdTRUE);
    multi_heap_info_t heap;
    heap_caps_get_info(&heap, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    allocation_totals tls = allocation_meter_read();
    printf("RESOURCE attempt=%u phase=%s requested=%zu peak=%zu core=%zu crypto=%zu live=%u allocations=%u"
           " free=%zu largest=%zu minimum=%zu main_stack_free=%u tcp_stack_free=%u active=%u timewait=%u dns=%u\n",
           attempt, phase, tls.bytes, tls.peak, tls.core_bytes, tls.crypto_bytes, tls.live, tls.allocations,
           heap.total_free_bytes, heap.largest_free_block, heap.minimum_free_bytes,
           (unsigned)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)), network.tcp_stack_free,
           network.active, network.timewait, lwip_dns_pending());
    check(heap_caps_check_integrity_all(true), "heap metadata integrity");
    if (!strcmp(phase, "settled")) {
        check(tls.bytes == 0 && tls.live == 0 && tls.core_bytes == 0 && tls.crypto_bytes == 0,
              "tracked allocations returned to zero");
        check(network.active == 0 && lwip_dns_pending() == 0, "no active connection or pending lookup");
    }
    allocation_meter_pause(false);
}

static void exchange(tls_stream *stream, void (*check)(bool, const char *))
{
    static const uint8_t request[] = "GET /probe HTTP/1.1\r\nHost: tls.lab.test\r\nConnection: close\r\n\r\n";
    static const uint8_t expected[] = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n"
#if LAB_ECDSA
        "\x00\xff\x80\r\nA\x00\n";
#else
        "lwip-ok\n";
#endif
    uint8_t response[256];
    size_t sent = 0, received = 0;
    int count = -1;
    while (sent < sizeof(request) - 1) {
        count = tls_stream_write(stream, request + sent, sizeof(request) - 1 - sent);
        if (count <= 0) break;
        sent += (size_t)count;
    }
    while (received < sizeof(response) &&
           (count = tls_stream_read(stream, response + received, sizeof(response) - received)) > 0)
        received += (size_t)count;
    check(sent == sizeof(request) - 1 && received == sizeof(expected) - 1 && !memcmp(response, expected, received),
          "exact authenticated exchange");
    check(count == 0 && tls_stream_status(stream) == TLS_OK, "authenticated EOF");
}

void resource_probe(bool ready, void (*check)(bool, const char *))
{
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    configASSERT(done);
    printf("RESOURCE_CONFIG cycles=4 stack_element=%zu main_stack=%u tcp_stack=%u tracker_capacity=256\n",
           sizeof(StackType_t), CONFIG_ESP_MAIN_TASK_STACK_SIZE, TCPIP_THREAD_STACKSIZE);
    check(sizeof(StackType_t) == 1, "stack watermark byte units verified");
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        bool rejection = attempt % 2;
        printf("ATTEMPT resource-%u-%s\n", attempt, rejection ? "reject" : "valid");
        allocation_meter_begin();
        report(attempt, "before", done, check);
        idf_transport transport;
        check(idf_transport_init(&transport, lab_root, sizeof(lab_root)) == 0, "root parsed");
        transport.clock_ready = ready;
        report(attempt, "root", done, check);
        tls_stream_port port = idf_transport_port(&transport);
        tls_stream *stream = tls_stream_create(&port);
        check(stream != NULL, "stream allocated");
        report(attempt, "created", done, check);
        tls_status status = tls_stream_open(stream, "192.0.2.1", rejection ? 8444 : 8443, 5000);
        tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
        check(status == (rejection ? TLS_ERROR : TLS_OK) && diagnostic.stage == TLS_STAGE_HANDSHAKE &&
              diagnostic.code == (rejection ? MBEDTLS_ERR_X509_CERT_VERIFY_FAILED : 0) &&
              diagnostic.verify_flags == (rejection ? MBEDTLS_X509_BADCERT_CN_MISMATCH : 0), "exact resource-case diagnostic");
        report(attempt, "opened", done, check);
        if (!rejection && status == TLS_OK) exchange(stream, check);
        else if (rejection) {
            uint8_t byte = 0xa5;
            check(tls_stream_read(stream, &byte, 1) == -1 && byte == 0xa5, "rejected read preserves output");
            check(tls_stream_write(stream, &byte, 1) == -1, "rejected write refused");
        }
        printf("RESOURCE_RESULT attempt=%u status=%d stage=%d code=%d verify=%lu opens=%u\n",
               attempt, status, diagnostic.stage, diagnostic.code, (unsigned long)diagnostic.verify_flags, transport.open_calls);
        tls_stream_destroy(stream);
        idf_transport_destroy(&transport);
        check(transport.socket_fd == -1, "destroy released socket");
        report(attempt, "destroyed", done, check);
        vTaskDelay(pdMS_TO_TICKS(500));
        report(attempt, "settled", done, check);
        allocation_meter_end();
    }
    allocation_meter_begin();
    report(8, "cooldown-start", done, check);
    int64_t until = esp_timer_get_time() + 135000000LL;
    network_snapshot network;
    do {
        network = (network_snapshot){.done = done};
        configASSERT(tcpip_callback(capture_network, &network) == ERR_OK);
        configASSERT(xSemaphoreTake(done, pdMS_TO_TICKS(1000)) == pdTRUE);
        if (!network.active && !network.timewait) break;
        vTaskDelay(pdMS_TO_TICKS(2000));
    } while (esp_timer_get_time() < until);
    check(network.active == 0 && network.timewait == 0, "TCP records expired on natural timers");
    report(8, "cooldown-end", done, check);
    allocation_meter_end();
    vSemaphoreDelete(done);
}
