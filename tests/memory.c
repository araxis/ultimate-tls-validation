#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "memory.h"
#include "allocations.h"
#include "lwip_transport.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "lwip/tcpip.h"
#include "lwip/stats.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/priv/memp_priv.h"
#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#if MEMP_MEM_MALLOC || MEM_LIBC_MALLOC || !MEM_STATS || !MEMP_STATS || !SYS_STATS
#error "Memory accounting requires the reference port's separate lwIP heap and pools"
#endif

static const char *const pool_names[] = {
#define LWIP_MEMPOOL(name, num, size, description) #name,
#include "lwip/priv/memp_std.h"
#undef LWIP_MEMPOOL
};

struct snapshot {
    SemaphoreHandle_t ready;
    struct stats_mem heap, pools[MEMP_MAX];
    struct stats_sys sys;
    unsigned active, timewait;
    HeapStats_t rtos;
};

static void capture(void *context)
{
    struct snapshot *s = context;
    taskENTER_CRITICAL();
    s->heap = lwip_stats.mem;
    s->sys = lwip_stats.sys;
    for (unsigned i = 0; i < MEMP_MAX; ++i) s->pools[i] = *lwip_stats.memp[i];
    for (struct tcp_pcb *p = tcp_active_pcbs; p; p = p->next) ++s->active;
    for (struct tcp_pcb *p = tcp_tw_pcbs; p; p = p->next) ++s->timewait;
    taskEXIT_CRITICAL();
    xSemaphoreGive(s->ready);
}

static struct snapshot sample(SemaphoreHandle_t ready)
{
    struct snapshot s = {.ready = ready};
    configASSERT(tcpip_callback(capture, &s) == ERR_OK);
    configASSERT(xSemaphoreTake(ready, pdMS_TO_TICKS(2000)) == pdTRUE);
    vPortGetHeapStats(&s.rtos);
    return s;
}

static void report(const char *phase, unsigned cycle, const struct snapshot *s)
{
    struct allocation_measurement tls = allocation_measure_read();
    struct mallinfo2 host = mallinfo2();
    printf("MEMORY phase=%s cycle=%u tls_live=%u tls_bytes=%zu tls_peak=%zu rtos_free=%zu rtos_largest=%zu"
           " rtos_min=%zu lwip_used=%lu lwip_peak=%lu sem=%u mbox=%u mutex=%u active=%u timewait=%u"
           " host_allocated=%zu host_free=%zu host_arena=%zu host_mapped=%zu\n",
           phase, cycle, tls.live, tls.bytes, tls.peak, s->rtos.xAvailableHeapSpaceInBytes,
           s->rtos.xSizeOfLargestFreeBlockInBytes, s->rtos.xMinimumEverFreeBytesRemaining,
           (unsigned long)s->heap.used, (unsigned long)s->heap.max,
           (unsigned)s->sys.sem.used, (unsigned)s->sys.mbox.used, (unsigned)s->sys.mutex.used,
           s->active, s->timewait, host.uordblks, host.fordblks, host.arena, host.hblkhd);
    for (unsigned i = 0; i < MEMP_MAX; ++i) {
        printf("MEMPOOL phase=%s cycle=%u name=%s item_bytes=%u capacity=%u used=%lu peak=%lu\n",
               phase, cycle, pool_names[i], memp_pools[i]->size, memp_pools[i]->num,
               (unsigned long)s->pools[i].used, (unsigned long)s->pools[i].max);
    }
}

static void check(struct memory_results *r, bool passed, const char *label)
{
    ++r->checks;
    if (!passed) ++r->failures;
    printf("%s memory: %s\n", passed ? "PASS" : "FAIL", label);
}

struct memory_results memory_tests(const char *ca_path)
{
    struct memory_results result = {0};
    SemaphoreHandle_t ready = xSemaphoreCreateBinary();
    configASSERT(ready);
    pthread_attr_t attr;
    size_t pthread_stack;
    configASSERT(pthread_getattr_np(pthread_self(), &attr) == 0);
    configASSERT(pthread_attr_getstacksize(&attr, &pthread_stack) == 0);
    configASSERT(pthread_attr_destroy(&attr) == 0);
    printf("MEMORY_CONFIG rtos_reserved=%u lwip_reserved=%u stack_word=%zu client_pthread_stack=%zu tasks=%u\n",
           (unsigned)configTOTAL_HEAP_SIZE, (unsigned)MEM_SIZE, sizeof(StackType_t),
           pthread_stack, (unsigned)uxTaskGetNumberOfTasks());
    printf("MEMORY_ALLOCATOR tunables=%s\n", getenv("GLIBC_TUNABLES") ? getenv("GLIBC_TUNABLES") : "default");
    allocation_measure_begin();
    struct snapshot cold = sample(ready), baseline = cold;
    report("cold", 0, &cold);
    for (unsigned cycle = 0; cycle < 4; ++cycle) {
        lwip_transport transports[2];
        tls_stream *streams[2];
        for (unsigned i = 0; i < 2; ++i) {
            configASSERT(lwip_transport_init(&transports[i], ca_path) == 0);
            tls_stream_port port = lwip_transport_port(&transports[i]);
            streams[i] = tls_stream_create(&port);
            configASSERT(streams[i]);
            check(&result, tls_stream_open(streams[i], "tls.lab.test", (uint16_t)(8477 + i), 10000) == TLS_OK,
                  "verified session opened");
        }
        struct snapshot live = sample(ready);
        report("live", cycle, &live);
        check(&result, live.active == 2 && live.pools[MEMP_NETCONN].used == baseline.pools[MEMP_NETCONN].used + 2,
              "two live sockets accounted");
        check(&result, allocation_measure_read().bytes > 0, "TLS live allocations recorded");
        for (unsigned i = 0; i < 2; ++i) {
            uint8_t byte = (uint8_t)(cycle * 2 + i);
            check(&result, tls_stream_write(streams[i], &byte, 1) == 1 &&
                  tls_stream_read(streams[i], &byte, 1) == 1 && byte == 'Y' &&
                  tls_stream_read(streams[i], &byte, 1) == 0 && tls_stream_status(streams[i]) == TLS_OK,
                  "payload and authenticated EOF verified");
            tls_stream_destroy(streams[i]);
            lwip_transport_destroy(&transports[i]);
            check(&result, transports[i].socket_fd == -1, "socket released");
        }
        struct snapshot closed = sample(ready);
        report("closed", cycle, &closed);
        /* Observe real elapsed settling, without advancing or editing TCP timers. */
        vTaskDelay(pdMS_TO_TICKS(2000));
        struct snapshot settled = sample(ready);
        report("settled", cycle, &settled);
        check(&result, allocation_measure_read().bytes == 0 && allocation_measure_read().live == 0,
              "tracked TLS allocations return to zero");
        check(&result, settled.active == 0 && settled.pools[MEMP_NETCONN].used == baseline.pools[MEMP_NETCONN].used,
              "active connections and netconns return to baseline");
        check(&result, settled.heap.used == baseline.heap.used &&
              settled.pools[MEMP_TCP_SEG].used == baseline.pools[MEMP_TCP_SEG].used &&
              settled.pools[MEMP_PBUF_POOL].used == baseline.pools[MEMP_PBUF_POOL].used,
              "network payload storage returns to baseline");
        check(&result, settled.pools[MEMP_TCP_PCB].used == settled.timewait && settled.timewait <= 8,
              "remaining TCP PCBs are bounded TIME_WAIT state");
        if (cycle == 0) {
            baseline = settled; /* Separate persistent DNS initialization from per-session cost. */
        } else {
            check(&result, settled.rtos.xAvailableHeapSpaceInBytes == baseline.rtos.xAvailableHeapSpaceInBytes &&
                  settled.sys.sem.used == baseline.sys.sem.used && settled.sys.mbox.used == baseline.sys.mbox.used,
                  "warm RTOS heap and IPC counts return to baseline");
        }
        printf("RESULT memory-cycle index=%u warmup=%u\n", cycle, (unsigned)(cycle == 0));
    }
    TickType_t start = xTaskGetTickCount();
    struct snapshot expired = sample(ready);
    while ((expired.timewait || expired.active) && xTaskGetTickCount() - start < pdMS_TO_TICKS(140000)) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        expired = sample(ready);
    }
    report("expired", 4, &expired);
    printf("RETENTION elapsed_ticks=%lu tick_hz=%u\n", (unsigned long)(xTaskGetTickCount() - start), configTICK_RATE_HZ);
    check(&result, expired.timewait == 0 && expired.active == 0 && expired.pools[MEMP_TCP_PCB].used == 0,
          "natural TCP timer expiry reclaims retained PCBs");
    check(&result, expired.rtos.xAvailableHeapSpaceInBytes == baseline.rtos.xAvailableHeapSpaceInBytes &&
          expired.heap.used == baseline.heap.used && expired.pools[MEMP_NETCONN].used == 0,
          "post-expiry RTOS and network heap stay at baseline");
    struct allocation_measurement end = allocation_measure_end();
    check(&result, end.live == 0 && end.bytes == 0, "accounting ends without tracked TLS retention");
    vSemaphoreDelete(ready);
    return result;
}
