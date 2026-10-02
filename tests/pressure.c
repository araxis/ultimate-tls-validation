#include "pressure.h"
#include "lwip_transport.h"
#include "lwip_dns.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "lwip/tcpip.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#include "lwip/memp.h"
#include "lwip/stats.h"
#include <stdio.h>
#include <string.h>

static struct pressure_results results;

static void check(bool passed, const char *label)
{
    ++results.checks;
    if (!passed) ++results.failures;
    printf("%s %s\n", passed ? "PASS" : "FAIL", label);
}

static unsigned pool_used(memp_t pool)
{
    taskENTER_CRITICAL();
    unsigned used = lwip_stats.memp[pool]->used;
    taskEXIT_CRITICAL();
    return used;
}

static void dns_pool(const char *ca_path)
{
    configASSERT(lwip_dns_pending() == 0);
    for (unsigned index = 0; index < DNS_TABLE_SIZE; ++index) {
        char hostname[64];
        snprintf(hostname, sizeof(hostname), "pool-%u.lab.test", index);
        lwip_transport transport;
        configASSERT(lwip_transport_init(&transport, ca_path) == 0);
        tls_stream_port port = lwip_transport_port(&transport);
        tls_stream *stream = tls_stream_create(&port);
        configASSERT(stream);
        int64_t start = port.now_ms(&transport);
        tls_status status = tls_stream_open(stream, hostname, 8443, 50);
        int64_t elapsed = port.now_ms(&transport) - start;
        check(status == TLS_TIMEOUT, "pool fill times out at caller");
        check(elapsed >= 0 && elapsed <= 300, "pool fill wait bounded");
        check(lwip_dns_pending() == index + 1, "pending lookup retained until DNS callback");
        tls_stream_destroy(stream);
        check(transport.socket_fd == -1, "pool fill has no socket");
        lwip_transport_destroy(&transport);
        printf("RESULT dns-pool-fill index=%u elapsed_ms=%lld\n", index, (long long)elapsed);
    }
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca_path) == 0);
    tls_stream_port port = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    int64_t start = port.now_ms(&transport);
    tls_status status = tls_stream_open(stream, "overflow.lab.test", 8443, 1000);
    int64_t elapsed = port.now_ms(&transport) - start;
    check(status == TLS_TRANSPORT_ERROR, "full DNS pool rejects another lookup");
    check(elapsed >= 0 && elapsed <= 250, "pool exhaustion fails promptly");
    check(lwip_dns_pending() == DNS_TABLE_SIZE, "DNS pool stays bounded");
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "rejected lookup has no socket");
    lwip_transport_destroy(&transport);
    printf("RESULT dns-pool-full elapsed_ms=%lld\n", (long long)elapsed);
    vTaskDelay(pdMS_TO_TICKS(3000));
    check(lwip_dns_pending() == 0, "timed-out DNS callbacks release saturated pool");
}

struct core_gate {
    SemaphoreHandle_t entered;
    SemaphoreHandle_t release;
};

static void hold_core(void *context)
{
    struct core_gate *gate = context;
    xSemaphoreGive(gate->entered);
    /* Test-only bounded gate. An unexpected blocked caller fails the process. */
    configASSERT(xSemaphoreTake(gate->release, pdMS_TO_TICKS(2000)) == pdTRUE);
}

static void signal_barrier(void *context)
{
    xSemaphoreGive((SemaphoreHandle_t)context);
}

static void drain_core(void)
{
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    configASSERT(done);
    configASSERT(tcpip_callback(signal_barrier, done) == ERR_OK);
    configASSERT(xSemaphoreTake(done, pdMS_TO_TICKS(2000)) == pdTRUE);
    vSemaphoreDelete(done);
}

static void enter_gate(struct core_gate *gate)
{
    gate->entered = xSemaphoreCreateBinary();
    gate->release = xSemaphoreCreateBinary();
    configASSERT(gate->entered && gate->release);
    configASSERT(tcpip_try_callback(hold_core, gate) == ERR_OK);
    configASSERT(xSemaphoreTake(gate->entered, pdMS_TO_TICKS(1000)) == pdTRUE);
}

static void leave_gate(struct core_gate *gate)
{
    xSemaphoreGive(gate->release);
    drain_core();
    vSemaphoreDelete(gate->entered);
    vSemaphoreDelete(gate->release);
}

static void count_callback(void *context)
{
    unsigned *count = context;
    ++*count;
}

static void dns_queue(const char *ca_path, bool full)
{
    drain_core();
    unsigned initial_messages = pool_used(MEMP_TCPIP_MSG_API);
    struct core_gate gate;
    unsigned completed = 0, posted = 0;
    struct tcpip_callback_msg *message = NULL;
    enter_gate(&gate);
    if (full) {
        /* A reusable message fills queue slots without exhausting the separate
         * callback-message allocation pool first. No message state is modified. */
        message = tcpip_callbackmsg_new(count_callback, &completed);
        configASSERT(message);
        while (posted <= TCPIP_MBOX_SIZE && tcpip_callbackmsg_trycallback(message) == ERR_OK) ++posted;
        check(posted > 0 && posted <= TCPIP_MBOX_SIZE, "real TCP/IP mailbox filled");
    }
    unsigned held_messages = pool_used(MEMP_TCPIP_MSG_API);
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca_path) == 0);
    tls_stream_port port = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    int64_t start = port.now_ms(&transport);
    tls_status status = tls_stream_open(stream, full ? "queue-full.lab.test" : "queue-expired.lab.test", 8443, 100);
    int64_t elapsed = port.now_ms(&transport) - start;
    check(status == (full ? TLS_TRANSPORT_ERROR : TLS_TIMEOUT), "queued DNS has expected failure");
    check(elapsed >= 0 && elapsed <= (full ? 250 : 350), "queued DNS wait bounded");
    check(lwip_dns_pending() == (full ? 0U : 1U), "queued DNS reference ownership");
    if (full) check(pool_used(MEMP_TCPIP_MSG_API) == held_messages, "failed enqueue frees message allocation");
    tls_stream_destroy(stream);
    if (!full) check(transport.socket_fd == -1, "expired queued lookup has no socket");
    lwip_transport_destroy(&transport);
    leave_gate(&gate);
    if (full) {
        check(completed == posted, "all queued callbacks completed before release");
        tcpip_callbackmsg_delete(message);
    } else {
        check(lwip_dns_pending() == 0, "abandoned callback releases slot without querying DNS");
    }
    check(pool_used(MEMP_TCPIP_MSG_API) == initial_messages, "callback message allocations restored");
    printf("RESULT %s queued=%u elapsed_ms=%lld\n", full ? "dns-queue-full" : "dns-queued-timeout",
           posted, (long long)elapsed);
}

struct write_observer {
    lwip_transport *transport;
    tls_stream_port port;
    SemaphoreHandle_t done;
    bool cancel, blocked;
    int64_t cancelled_ms;
};

static void observe_backpressure(void *context)
{
    struct write_observer *observer = context;
    int64_t start = observer->port.now_ms(observer->transport);
    int fd = observer->transport->socket_fd;
    while (observer->port.now_ms(observer->transport) - start < 1000) {
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(fd, &writable);
        struct timeval immediate = {0, 0};
        if (lwip_select(fd + 1, NULL, &writable, NULL, &immediate) == 0) {
            observer->blocked = true;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    if (observer->cancel && observer->blocked) {
        vTaskDelay(pdMS_TO_TICKS(50));
        observer->cancelled_ms = observer->port.now_ms(observer->transport);
        lwip_transport_cancel(observer->transport);
    }
    xSemaphoreGive(observer->done);
    vTaskDelete(NULL);
}

static void write_pressure(const char *ca_path, bool cancel)
{
    unsigned initial_connections = pool_used(MEMP_NETCONN);
    unsigned initial_pcbs = pool_used(MEMP_TCP_PCB);
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca_path) == 0);
    tls_stream_port port = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    int64_t start = port.now_ms(&transport);
    tls_status opened = tls_stream_open(stream, "tls.lab.test", 8447, cancel ? 5000 : 500);
    check(opened == TLS_OK, "write pressure starts with verified TLS");
    uint8_t ready = 0;
    bool peer_ready = opened == TLS_OK && tls_stream_read(stream, &ready, 1) == 1 && ready == 1;
    check(peer_ready, "peer confirms it will stop reading");
    if (!peer_ready) {
        tls_stream_destroy(stream);
        lwip_transport_destroy(&transport);
        return;
    }
    struct write_observer observer = {.transport = &transport, .port = port, .cancel = cancel};
    observer.done = xSemaphoreCreateBinary();
    configASSERT(observer.done);
    configASSERT(xTaskCreate(observe_backpressure, "write-observer", 4096, &observer, 2, NULL) == pdPASS);
    uint8_t bytes[512];
    memset(bytes, 0x5a, sizeof(bytes));
    size_t sent = 0;
    int count = 0;
    while (sent < 8 * 1024 * 1024 && (count = tls_stream_write(stream, bytes, sizeof(bytes))) > 0) {
        sent += (size_t)count;
    }
    int64_t finished = port.now_ms(&transport);
    tls_status status = tls_stream_status(stream);
    configASSERT(xSemaphoreTake(observer.done, pdMS_TO_TICKS(1500)) == pdTRUE);
    vSemaphoreDelete(observer.done);
    check(observer.blocked, "lwIP socket became non-writable");
    check(count < 0 && status == (cancel ? TLS_CANCELLED : TLS_TIMEOUT), "backpressure has expected failure");
    check(tls_stream_diagnostic(stream).stage == TLS_STAGE_WRITE, "backpressure failed in write phase");
    int64_t elapsed = finished - (cancel ? observer.cancelled_ms : start);
    check(elapsed >= 0 && elapsed <= (cancel ? 250 : 750), "backpressure return bounded");
    check(sent > 0 && sent < 8 * 1024 * 1024, "bounded bytes queued before backpressure");
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "write pressure socket released");
    lwip_transport_destroy(&transport);
    check(pool_used(MEMP_NETCONN) == initial_connections, "netconn pool restored after write failure");
    check(pool_used(MEMP_TCP_PCB) == initial_pcbs, "TCP PCB pool restored after write failure");
    printf("RESULT %s bytes=%lu elapsed_ms=%lld\n", cancel ? "write-cancel" : "write-timeout",
           (unsigned long)sent, (long long)elapsed);
}

struct pressure_results pressure_tests(const char *ca_path)
{
    results = (struct pressure_results){0};
    printf("PRESSURE dns_capacity=%u mailbox_capacity=%u\n", DNS_TABLE_SIZE, TCPIP_MBOX_SIZE);
    dns_pool(ca_path);
    dns_queue(ca_path, true);
    dns_queue(ca_path, false);
    write_pressure(ca_path, false);
    write_pressure(ca_path, true);
    return results;
}
