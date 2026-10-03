#include "exhaustion.h"
#include "allocations.h"
#include "lwip_transport.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "lwip/tcpip.h"
#include "lwip/memp.h"
#include "lwip/stats.h"
#include <stdio.h>

static struct exhaustion_results results;

static void check(bool passed, const char *label)
{
    ++results.checks;
    if (!passed) ++results.failures;
    printf("%s exhaustion: %s\n", passed ? "PASS" : "FAIL", label);
}

static bool roundtrip(tls_stream *stream)
{
    uint8_t byte = 'K';
    return tls_stream_write(stream, &byte, 1) == 1 &&
           tls_stream_read(stream, &byte, 1) == 1 && byte == 'Y' &&
           tls_stream_read(stream, &byte, 1) == 0 && tls_stream_status(stream) == TLS_OK;
}

static void recovery(const char *ca_path, const char *label, uint16_t number)
{
    allocation_measure_begin();
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca_path) == 0);
    tls_stream_port port = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    check(tls_stream_open(stream, "tls.lab.test", number, 3000) == TLS_OK && roundtrip(stream),
          "authenticated exchange after resource release");
    tls_stream_destroy(stream);
    lwip_transport_destroy(&transport);
    struct allocation_measurement final = allocation_measure_end();
    check(final.live == 0 && final.bytes == 0 && transport.socket_fd == -1,
          "recovery leaves no tracked TLS allocation or socket");
    printf("RESULT %s peak=%zu\n", label, final.peak);
}

/* This is a sustained requested-byte ceiling, not a one-shot allocation
 * failure. One live stream keeps its allocations while another is attempted. */
static void tls_budget(const char *ca_path, unsigned cycle)
{
    allocation_measure_begin();
    lwip_transport first;
    configASSERT(lwip_transport_init(&first, ca_path) == 0);
    tls_stream_port port = lwip_transport_port(&first);
    tls_stream *live = tls_stream_create(&port);
    configASSERT(live);
    check(tls_stream_open(live, "tls.lab.test", 8464, 5000) == TLS_OK,
          "first session established before allocation pressure");
    struct allocation_measurement baseline = allocation_measure_read();
    for (unsigned phase = 0; phase < 2; ++phase) {
        size_t limit = baseline.bytes + (phase ? baseline.bytes : 8192);
        allocation_measure_limit(limit);
        lwip_transport second;
        configASSERT(lwip_transport_init(&second, ca_path) == 0);
        tls_stream_port second_port = lwip_transport_port(&second);
        tls_stream *stream = tls_stream_create(&second_port);
        configASSERT(stream);
        unsigned rejected = allocation_measure_read().rejected;
        int64_t start = port.now_ms(&first);
        tls_status status = tls_stream_open(stream, "tls.lab.test", 8479, 1000);
        int64_t elapsed = port.now_ms(&first) - start;
        tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
        struct allocation_measurement failed = allocation_measure_read();
        check(failed.rejected > rejected && failed.bytes <= limit,
              "sustained TLS byte limit actually rejects an allocation");
        check(status == TLS_ERROR && diagnostic.stage == (phase ? TLS_STAGE_HANDSHAKE : TLS_STAGE_SETUP),
              "allocation failure is attributed to setup or handshake");
        check(elapsed >= 0 && elapsed <= 1250, "allocation failure returns within the deadline allowance");
        check(second.socket_fd == -1, "failed second session releases its socket immediately");
        tls_stream_destroy(stream);
        lwip_transport_destroy(&second);
        struct allocation_measurement after = allocation_measure_read();
        check(after.live == baseline.live && after.bytes == baseline.bytes,
              "failed second session restores first session allocation baseline");
        printf("EXHAUST_TLS cycle=%u phase=%u limit=%zu rejected=%u live=%u bytes=%zu stage=%d status=%d elapsed_ms=%lld\n",
               cycle, phase, limit, failed.rejected - rejected, after.live, after.bytes,
               diagnostic.stage, status, (long long)elapsed);
    }
    allocation_measure_limit(SIZE_MAX);
    check(roundtrip(live), "existing authenticated session survives another session's memory failure");
    tls_stream_destroy(live);
    lwip_transport_destroy(&first);
    struct allocation_measurement final = allocation_measure_end();
    check(final.live == 0 && final.bytes == 0 && first.socket_fd == -1,
          "both sessions release all tracked allocations and sockets");
    printf("RESULT tls-budget cycle=%u peak=%zu\n", cycle, final.peak);
    recovery(ca_path, "tls-budget-recovery", 8479);
}

struct snapshot {
    SemaphoreHandle_t ready;
    unsigned netconns, netconn_errors, sems, sem_errors, mboxes, mbox_errors;
    HeapStats_t heap;
};

static void capture(void *context)
{
    struct snapshot *s = context;
    taskENTER_CRITICAL();
    s->netconns = lwip_stats.memp[MEMP_NETCONN]->used;
    s->netconn_errors = lwip_stats.memp[MEMP_NETCONN]->err;
    s->sems = lwip_stats.sys.sem.used;
    s->sem_errors = lwip_stats.sys.sem.err;
    s->mboxes = lwip_stats.sys.mbox.used;
    s->mbox_errors = lwip_stats.sys.mbox.err;
    taskEXIT_CRITICAL();
    xSemaphoreGive(s->ready);
}

static struct snapshot sample(SemaphoreHandle_t ready)
{
    struct snapshot s = {.ready = ready};
    configASSERT(tcpip_callback(capture, &s) == ERR_OK);
    configASSERT(xSemaphoreTake(ready, pdMS_TO_TICKS(2000)) == pdTRUE);
    vPortGetHeapStats(&s.heap);
    return s;
}

/* Consume the real RTOS heap without allocating a new observer after it is
 * full. The TCP/IP callback and existing synchronization objects still run. */
static unsigned hold_heap(void **blocks, unsigned capacity)
{
    unsigned count = 0;
    while (count < capacity) {
        HeapStats_t heap;
        vPortGetHeapStats(&heap);
        size_t bytes = heap.xSizeOfLargestFreeBlockInBytes / 2;
        void *block = pvPortMalloc(bytes ? bytes : 1);
        if (!block) {
            block = pvPortMalloc(1);
            if (!block) return count;
        }
        blocks[count++] = block;
    }
    configASSERT(!"heap holder capacity exceeded");
    return count;
}

static void resource_limit(const char *ca_path, SemaphoreHandle_t ready, bool rtos, unsigned cycle)
{
    struct snapshot before = sample(ready);
    void *connections[MEMP_NUM_NETCONN];
    void *blocks[128];
    unsigned held = 0;
    if (rtos) {
        held = hold_heap(blocks, 128);
        void *unexpected = pvPortMalloc(1);
        check(held > 0 && unexpected == NULL, "real RTOS heap cannot satisfy a one-byte request");
        vPortFree(unexpected);
    } else {
        while (held < MEMP_NUM_NETCONN) {
            /* Hold actual pool entries without consuming TCP PCBs first.
             * These are fixture-owned raw slots, never initialized sockets. */
            void *entry = memp_malloc(MEMP_NETCONN);
            if (!entry) break;
            connections[held++] = entry;
        }
        struct snapshot full = sample(ready);
        check(held > 0 && full.netconns == MEMP_NUM_NETCONN, "real lwIP netconn pool is full");
    }
    struct snapshot saturated = sample(ready);
    allocation_measure_begin();
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca_path) == 0);
    tls_stream_port port = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    int64_t start = port.now_ms(&transport);
    tls_status status = tls_stream_open(stream, "tls.lab.test", 8464, 1000);
    int64_t elapsed = port.now_ms(&transport) - start;
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    check(status == TLS_TRANSPORT_ERROR && diagnostic.stage == TLS_STAGE_TCP_OPEN,
          "network resource exhaustion returns an attributed transport failure");
    check(elapsed >= 0 && elapsed <= 1250, "network resource failure stays bounded");
    check(transport.socket_fd == -1, "resource failure does not retain a socket");
    tls_stream_destroy(stream);
    lwip_transport_destroy(&transport);
    struct allocation_measurement final = allocation_measure_end();
    check(final.live == 0 && final.bytes == 0 && final.rejected == 0,
          "transport failure cleans TLS allocations without a TLS allocation rejection");
    struct snapshot failed = sample(ready);
    check(rtos ? failed.mbox_errors > saturated.mbox_errors : failed.netconn_errors > saturated.netconn_errors,
          "resource counters confirm the actual exhausted layer");
    check(failed.netconns == saturated.netconns && failed.sems == saturated.sems && failed.mboxes == saturated.mboxes,
          "partial socket construction leaves no extra pool or IPC object");
    for (unsigned i = 0; i < held; ++i) {
        if (rtos) vPortFree(blocks[i]);
        else memp_free(MEMP_NETCONN, connections[i]);
    }
    struct snapshot after = sample(ready);
    check(after.netconns == before.netconns && after.sems == before.sems && after.mboxes == before.mboxes,
          "held resources return to their pre-pressure counts");
    check(after.heap.xAvailableHeapSpaceInBytes == before.heap.xAvailableHeapSpaceInBytes,
          "RTOS available heap returns to the pre-pressure baseline");
    printf("RESULT %s cycle=%u held=%u free_before=%zu free_saturated=%zu free_after=%zu netconn_errors=%u sem_errors=%u mbox_errors=%u elapsed_ms=%lld\n",
           rtos ? "rtos-exhaustion" : "netconn-exhaustion", cycle, held,
           before.heap.xAvailableHeapSpaceInBytes, saturated.heap.xAvailableHeapSpaceInBytes,
           after.heap.xAvailableHeapSpaceInBytes, failed.netconn_errors - saturated.netconn_errors,
           failed.sem_errors - saturated.sem_errors, failed.mbox_errors - saturated.mbox_errors, (long long)elapsed);
    recovery(ca_path, rtos ? "rtos-recovery" : "netconn-recovery", 8464);
}

struct exhaustion_results exhaustion_tests(const char *ca_path)
{
    results = (struct exhaustion_results){0};
    SemaphoreHandle_t ready = xSemaphoreCreateBinary();
    configASSERT(ready);
    for (unsigned cycle = 0; cycle < 2; ++cycle) {
        tls_budget(ca_path, cycle);
        resource_limit(ca_path, ready, false, cycle);
        resource_limit(ca_path, ready, true, cycle);
    }
    vSemaphoreDelete(ready);
    return results;
}
