#include "sessions.h"
#include "lwip_transport.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "lwip/tcpip.h"
#include "lwip/memp.h"
#include "lwip/stats.h"
#include "lwip/priv/tcp_priv.h"
#include <stdio.h>
#include <string.h>

enum boundary { NONE, OPEN, READ, WRITE };
struct adapter {
    lwip_transport transport;
    tls_stream_port base;
    enum boundary armed;
    SemaphoreHandle_t reached, cancelled;
    unsigned short_reads, short_writes, closes;
    bool triggered;
};

static void rendezvous(struct adapter *a, enum boundary boundary, int result)
{
    if (a->armed != boundary || result < 0 || (boundary != OPEN && result == 0)) return;
    a->armed = NONE;
    a->triggered = true;
    xSemaphoreGive(a->reached);
    configASSERT(xSemaphoreTake(a->cancelled, pdMS_TO_TICKS(1000)) == pdTRUE);
}

static int64_t now(void *p) { struct adapter *a = p; return a->base.now_ms(&a->transport); }
static bool clock_ready(void *p) { struct adapter *a = p; return a->base.time_ready(&a->transport); }
static bool cancelled(void *p) { struct adapter *a = p; return a->base.cancelled(&a->transport); }
static int entropy(void *p, unsigned char *b, size_t n) { struct adapter *a = p; return a->base.entropy(&a->transport, b, n); }
static int trust(void *p, mbedtls_ssl_config *c) { struct adapter *a = p; return a->base.trust(&a->transport, c); }
static void close_port(void *p) { struct adapter *a = p; ++a->closes; a->base.close(&a->transport); }

static int open_port(void *p, const char *host, uint16_t port, uint32_t budget)
{
    struct adapter *a = p;
    int result = a->base.open(&a->transport, host, port, budget);
    rendezvous(a, OPEN, result);
    return result;
}

static int read_port(void *p, uint8_t *bytes, size_t length, uint32_t budget)
{
    struct adapter *a = p;
    int result = a->base.read(&a->transport, bytes, length > 13 ? 13 : length, budget);
    if (result > 0 && (size_t)result < length) ++a->short_reads;
    rendezvous(a, READ, result);
    return result;
}

static int write_port(void *p, const uint8_t *bytes, size_t length, uint32_t budget)
{
    struct adapter *a = p;
    int result = a->base.write(&a->transport, bytes, length > 17 ? 17 : length, budget);
    if (result > 0 && (size_t)result < length) ++a->short_writes;
    rendezvous(a, WRITE, result);
    return result;
}

static void cancellation_task(void *p)
{
    struct adapter *a = p;
    configASSERT(xSemaphoreTake(a->reached, pdMS_TO_TICKS(20000)) == pdTRUE);
    lwip_transport_cancel(&a->transport);
    xSemaphoreGive(a->cancelled);
    vTaskDelete(NULL);
}

struct worker {
    const char *ca, *label;
    uint16_t port;
    enum boundary boundary;
    bool before_open;
    SemaphoreHandle_t ready, proceed, done;
    struct session_results result;
    tls_status opened;
};

static void check(struct worker *w, bool passed, const char *label)
{
    ++w->result.checks;
    if (!passed) ++w->result.failures;
    printf("%s %s: %s\n", passed ? "PASS" : "FAIL", w->label, label);
}

static void run_session(struct worker *w)
{
    struct adapter a = {0};
    configASSERT(lwip_transport_init(&a.transport, w->ca) == 0);
    a.base = lwip_transport_port(&a.transport);
    tls_stream_port port = {.context = &a, .now_ms = now, .time_ready = clock_ready,
        .cancelled = cancelled, .entropy = entropy, .trust = trust, .open = open_port,
        .read = read_port, .write = write_port, .close = close_port};
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    if (w->boundary != NONE) {
        a.reached = xSemaphoreCreateBinary();
        a.cancelled = xSemaphoreCreateBinary();
        configASSERT(a.reached && a.cancelled);
        configASSERT(xTaskCreate(cancellation_task, "boundary-cancel", 4096, &a, 2, NULL) == pdPASS);
        if (w->boundary == OPEN) a.armed = OPEN;
    }
    if (w->before_open) lwip_transport_cancel(&a.transport);
    w->opened = tls_stream_open(stream, "tls.lab.test", w->port, 15000);
    bool opening_cancel = w->before_open || w->boundary == OPEN;
    check(w, w->opened == (opening_cancel ? TLS_CANCELLED : TLS_OK), "expected open status");
    if (w->ready) {
        xSemaphoreGive(w->ready);
        configASSERT(xSemaphoreTake(w->proceed, pdMS_TO_TICKS(2000)) == pdTRUE);
    }
    size_t sent = 0, received = 0;
    int last = -1;
    bool exact = true;
    uint8_t payload[1025], reply[19];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)(i * 37 + w->port);
    if (w->opened == TLS_OK) {
        a.armed = w->boundary == WRITE ? WRITE : NONE;
        while (sent < sizeof(payload)) {
            last = tls_stream_write(stream, payload + sent, sizeof(payload) - sent);
            if (last <= 0) break;
            sent += (size_t)last;
        }
        if (w->boundary != WRITE) {
            a.armed = w->boundary;
            while ((last = tls_stream_read(stream, reply, sizeof(reply))) > 0) {
                if (received + (size_t)last > sizeof(payload) ||
                    memcmp(reply, payload + received, (size_t)last) != 0) exact = false;
                received += (size_t)last;
                if (received > sizeof(payload)) break;
            }
        }
    }
    bool expect_cancel = opening_cancel || w->boundary != NONE;
    check(w, tls_stream_status(stream) == (expect_cancel ? TLS_CANCELLED : TLS_OK), "independent final status");
    if (w->boundary != NONE) {
        check(w, a.triggered, "selected completion boundary reached");
        tls_stage stage = w->boundary == OPEN ? TLS_STAGE_TCP_OPEN : w->boundary == READ ? TLS_STAGE_READ : TLS_STAGE_WRITE;
        check(w, tls_stream_diagnostic(stream).stage == stage, "cancellation reports expected phase");
    }
    if (!opening_cancel) {
        check(w, w->boundary == WRITE ? sent == 0 : sent == sizeof(payload), "expected application write result");
        check(w, expect_cancel ? last < 0 && received == 0 : last == 0 && received == sizeof(payload) && exact,
              "no duplicated, lost or exposed response bytes");
        check(w, a.short_reads > 0 && a.short_writes > 0, "real transport performed short reads and writes");
    }
    tls_stream_destroy(stream);
    check(w, a.transport.socket_fd == -1, "session socket released");
    check(w, a.closes == (w->before_open ? 0U : 1U), "transport closed exactly once when attempted");
    if (w->boundary != NONE) {
        /* The rendezvous joins the cancellation task's final access to a.
         * Failure to reach it is a fixture error, not a passing test. */
        configASSERT(a.triggered);
        vSemaphoreDelete(a.reached);
        vSemaphoreDelete(a.cancelled);
    }
    lwip_transport_destroy(&a.transport);
    printf("RESULT %s checks=%u failures=%u sent=%lu received=%lu short_reads=%u short_writes=%u\n",
           w->label, w->result.checks, w->result.failures, (unsigned long)sent,
           (unsigned long)received, a.short_reads, a.short_writes);
}

static void session_task(void *p)
{
    struct worker *w = p;
    run_session(w);
    xSemaphoreGive(w->done);
    vTaskDelete(NULL);
}

struct pools {
    SemaphoreHandle_t done;
    unsigned netconn, pcb, segment, active, established, timewait;
    bool unexpected_timewait, expire_timewait;
};
static void capture_pools(void *p)
{
    struct pools *s = p;
    if (s->expire_timewait) {
        /* Advance only the TCP timer, with no live connections. This tests the
         * pinned stack's reclamation logic, not elapsed wall-clock behavior. */
        configASSERT(!tcp_active_pcbs && !tcp_bound_pcbs && !tcp_listen_pcbs.pcbs);
        for (unsigned i = 0; i <= 2 * TCP_MSL / TCP_SLOW_INTERVAL; ++i) tcp_slowtmr();
    }
    s->netconn = lwip_stats.memp[MEMP_NETCONN]->used;
    s->pcb = lwip_stats.memp[MEMP_TCP_PCB]->used;
    s->segment = lwip_stats.memp[MEMP_TCP_SEG]->used;
    for (struct tcp_pcb *pcb = tcp_active_pcbs; pcb; pcb = pcb->next) {
        ++s->active;
        if (pcb->state == ESTABLISHED) ++s->established;
    }
    for (struct tcp_pcb *pcb = tcp_tw_pcbs; pcb; pcb = pcb->next) {
        ++s->timewait;
        if (pcb->remote_port != 8453 && pcb->remote_port != 8455) s->unexpected_timewait = true;
    }
    xSemaphoreGive(s->done);
}

static struct pools snapshot(bool expire_timewait)
{
    struct pools s = {.done = xSemaphoreCreateBinary(), .expire_timewait = expire_timewait};
    configASSERT(s.done && tcpip_callback(capture_pools, &s) == ERR_OK);
    configASSERT(xSemaphoreTake(s.done, pdMS_TO_TICKS(1000)) == pdTRUE);
    vSemaphoreDelete(s.done);
    s.done = NULL;
    return s;
}

struct session_results session_tests(const char *ca)
{
    struct worker aggregate = {.label = "sessions"};
    struct pools before = snapshot(false);
    struct worker sequential[] = {
        {.ca = ca, .label = "cancel-before-open", .port = 8450, .before_open = true},
        {.ca = ca, .label = "cancel-after-open", .port = 8450, .boundary = OPEN},
        {.ca = ca, .label = "cancel-after-write", .port = 8451, .boundary = WRITE},
        {.ca = ca, .label = "cancel-after-read", .port = 8452, .boundary = READ},
        {.ca = ca, .label = "short-transfer", .port = 8453},
    };
    for (unsigned i = 0; i < sizeof(sequential) / sizeof(sequential[0]); ++i) {
        run_session(&sequential[i]);
        aggregate.result.checks += sequential[i].result.checks;
        aggregate.result.failures += sequential[i].result.failures;
    }
    struct worker concurrent[] = {
        {.ca = ca, .label = "concurrent-cancel", .port = 8454, .boundary = READ},
        {.ca = ca, .label = "concurrent-success", .port = 8455},
    };
    for (unsigned i = 0; i < 2; ++i) {
        concurrent[i].ready = xSemaphoreCreateBinary();
        concurrent[i].proceed = xSemaphoreCreateBinary();
        concurrent[i].done = xSemaphoreCreateBinary();
        configASSERT(concurrent[i].ready && concurrent[i].proceed && concurrent[i].done);
        configASSERT(xTaskCreate(session_task, "session", 32768, &concurrent[i], 1, NULL) == pdPASS);
    }
    for (unsigned i = 0; i < 2; ++i) configASSERT(xSemaphoreTake(concurrent[i].ready, pdMS_TO_TICKS(18000)) == pdTRUE);
    struct pools live = snapshot(false);
    check(&aggregate, concurrent[0].opened == TLS_OK && concurrent[1].opened == TLS_OK &&
          live.netconn == before.netconn + 2 && live.active == 2 && live.established == 2,
          "two verified sessions alive simultaneously");
    for (unsigned i = 0; i < 2; ++i) xSemaphoreGive(concurrent[i].proceed);
    for (unsigned i = 0; i < 2; ++i) {
        configASSERT(xSemaphoreTake(concurrent[i].done, pdMS_TO_TICKS(18000)) == pdTRUE);
        aggregate.result.checks += concurrent[i].result.checks;
        aggregate.result.failures += concurrent[i].result.failures;
        vSemaphoreDelete(concurrent[i].ready);
        vSemaphoreDelete(concurrent[i].proceed);
        vSemaphoreDelete(concurrent[i].done);
    }
    struct pools after = snapshot(false);
    for (unsigned i = 0; i < 100 && after.active; ++i) {
        vTaskDelay(pdMS_TO_TICKS(10));
        after = snapshot(false);
    }
    printf("RETENTION netconn=%u pcb=%u segment=%u active=%u timewait=%u\n",
           after.netconn, after.pcb, after.segment, after.active, after.timewait);
    check(&aggregate, before.netconn == after.netconn, "all session netconns released");
    check(&aggregate, after.active == 0 && after.pcb == after.timewait && after.timewait <= 2 &&
          !after.unexpected_timewait, "only successful sessions may retain bounded TIME_WAIT state");
    check(&aggregate, before.segment == after.segment, "all session TCP segments released");
    if (!after.active) after = snapshot(true);
    check(&aggregate, before.pcb == after.pcb, "TCP timer expiry reclaims TIME_WAIT PCBs");
    return aggregate.result;
}
