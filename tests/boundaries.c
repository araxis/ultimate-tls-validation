#include "boundaries.h"
#include "lwip_transport.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include <stdio.h>
#include <string.h>

enum event { NO_EVENT, OPENED, WRITTEN, BUFFERED, CLOSE_NOTIFY, FINISHED };
enum action { EXPIRE, CANCEL, BOTH };
struct adapter {
    lwip_transport transport;
    tls_stream_port base;
    enum event event;
    enum action action;
    unsigned checks_left, triggers, closes, reads, writes;
    uint32_t elapsed, read_budget, write_budget;
    uint8_t header[5];
    unsigned header_size, body_left;
    bool cipher_changed;
    SemaphoreHandle_t done;
};

static void cancel_task(void *context)
{
    struct adapter *a = context;
    lwip_transport_cancel(&a->transport);
    xSemaphoreGive(a->done);
    vTaskDelete(NULL);
}

static bool cancelled(void *context)
{
    struct adapter *a = context;
    if (a->checks_left && --a->checks_left == 0) {
        ++a->triggers;
        if (a->action != CANCEL) a->elapsed = 3000;
        if (a->action != EXPIRE) {
            configASSERT(xTaskCreate(cancel_task, "completion-cancel", 4096, a, 2, NULL) == pdPASS);
            configASSERT(xSemaphoreTake(a->done, pdMS_TO_TICKS(1000)) == pdTRUE);
        }
    }
    return a->base.cancelled(&a->transport);
}

/* Only the stream's monotonic clock is controlled. Certificate UTC and the
 * actual lwIP socket deadlines still use the reference port's real clocks. */
static int64_t now(void *p) { return 10000 + ((struct adapter *)p)->elapsed; }
static bool time_ready(void *p) { struct adapter *a = p; return a->base.time_ready(&a->transport); }
static int entropy(void *p, unsigned char *b, size_t n) { struct adapter *a = p; return a->base.entropy(&a->transport, b, n); }
static int trust(void *p, mbedtls_ssl_config *c) { struct adapter *a = p; return a->base.trust(&a->transport, c); }
static void close_port(void *p) { struct adapter *a = p; ++a->closes; a->base.close(&a->transport); }

static int open_port(void *p, const char *host, uint16_t port, uint32_t budget)
{
    struct adapter *a = p;
    int result = a->base.open(&a->transport, host, port, budget);
    if (result == 0 && a->event == OPENED) a->checks_left = 1;
    return result;
}

static void record_complete(struct adapter *a)
{
    if (a->header[0] == 20) a->cipher_changed = true;
    bool target = (a->event == FINISHED && a->cipher_changed && a->header[0] == 22) ||
                  (a->event == CLOSE_NOTIFY && a->header[0] == 21);
    if (target) {
        /* First check follows transport receive, second follows TLS decode. */
        a->checks_left = 2;
        a->event = NO_EVENT;
    }
    a->header_size = 0;
}

static int read_port(void *p, uint8_t *bytes, size_t length, uint32_t budget)
{
    struct adapter *a = p;
    ++a->reads;
    a->read_budget = budget;
    int result = a->base.read(&a->transport, bytes, length, budget);
    /* Observe record boundaries without changing or decrypting wire bytes. */
    for (int i = 0; i < result; ++i) {
        if (a->header_size < 5) {
            a->header[a->header_size++] = bytes[i];
            if (a->header_size == 5) {
                a->body_left = (unsigned)a->header[3] * 256 + a->header[4];
                if (a->body_left == 0) record_complete(a);
            }
        } else if (--a->body_left == 0) record_complete(a);
    }
    return result;
}

static int write_port(void *p, const uint8_t *bytes, size_t length, uint32_t budget)
{
    struct adapter *a = p;
    ++a->writes;
    a->write_budget = budget;
    int result = a->base.write(&a->transport, bytes, length, budget);
    if (result > 0 && a->event == WRITTEN) { a->checks_left = 1; a->event = NO_EVENT; }
    return result;
}

static struct boundary_results results;
static void check(bool passed, const char *label)
{
    ++results.checks;
    if (!passed) ++results.failures;
    printf("%s %s\n", passed ? "PASS" : "FAIL", label);
}

struct test_case {
    const char *name;
    enum event event;
    enum action action;
    bool before_write, cumulative, terminal;
};

static void run_case(const char *ca, const struct test_case *test, uint16_t number)
{
    struct adapter a = {.event = test->event == OPENED || test->event == FINISHED ? test->event : NO_EVENT,
                        .action = test->action};
    configASSERT(lwip_transport_init(&a.transport, ca) == 0);
    a.base = lwip_transport_port(&a.transport);
    a.done = xSemaphoreCreateBinary();
    configASSERT(a.done);
    tls_stream_port port = {.context = &a, .now_ms = now, .time_ready = time_ready,
        .cancelled = cancelled, .entropy = entropy, .trust = trust, .open = open_port,
        .read = read_port, .write = write_port, .close = close_port};
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    int64_t started = a.base.now_ms(&a.transport);
    bool opening = test->event == OPENED || test->event == FINISHED;
    tls_status expected = test->action == EXPIRE ? TLS_TIMEOUT : TLS_CANCELLED;
    tls_status opened = tls_stream_open(stream, "tls.lab.test", number, 3000);
    check(opened == (opening ? expected : TLS_OK), "boundary open has expected status");
    uint8_t bytes[32], untouched[32];
    memset(untouched, 0xa5, sizeof(untouched));
    memcpy(bytes, untouched, sizeof(bytes));
    unsigned reads_before = a.reads, writes_before = a.writes;
    int result = -1;
    bool data_unchanged = true, setup = true, budget_exact = true;
    if (!opening && opened == TLS_OK) {
        a.event = test->event;
        if (test->before_write) a.elapsed = 3000;
        if (test->cumulative) a.elapsed = 1000;
        result = tls_stream_write(stream, (const uint8_t *)"!", 1);
        if (test->cumulative) budget_exact = a.write_budget == 2000;
        if (!test->before_write && test->event != WRITTEN) {
            setup = result == 1;
            if (test->event == BUFFERED || test->cumulative) {
                if (test->cumulative) a.elapsed = 2000;
                setup = setup && tls_stream_read(stream, bytes, 1) == 1 && bytes[0] == 'b';
                if (test->cumulative) budget_exact = budget_exact && a.read_budget == 1000;
                reads_before = a.reads;
                memcpy(bytes, untouched, sizeof(bytes));
                if (test->cumulative) a.elapsed = 3000;
                else a.checks_left = 2;
            }
            result = tls_stream_read(stream, bytes, sizeof(bytes));
            data_unchanged = memcmp(bytes, untouched, sizeof(bytes)) == 0;
            if (test->terminal) {
                setup = setup && result == 0 && tls_stream_status(stream) == TLS_OK;
                reads_before = a.reads;
                a.elapsed = 3000;
                lwip_transport_cancel(&a.transport);
                result = tls_stream_read(stream, bytes, sizeof(bytes));
                expected = TLS_OK;
            }
        }
    }
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    tls_stage stage = opening ? test->event == OPENED ? TLS_STAGE_TCP_OPEN : TLS_STAGE_HANDSHAKE :
                      test->before_write || test->event == WRITTEN ? TLS_STAGE_WRITE : TLS_STAGE_READ;
    check(setup && budget_exact, "boundary prerequisites and cumulative budgets verified");
    check(diagnostic.status == expected && diagnostic.stage == stage, "boundary status and phase preserved");
    check(opening || (test->terminal ? result == 0 : result < 0), "completion reports expected result");
    check(data_unchanged, "unsuccessful or EOF read leaves caller buffer untouched");
    bool hooked = opening || test->event == WRITTEN || test->event == BUFFERED || test->event == CLOSE_NOTIFY;
    check(a.triggers == (hooked ? 1u : 0u), "selected completion check reached exactly once");
    check((test->event != BUFFERED && !test->cumulative && !test->terminal) || a.reads == reads_before,
          "buffered and terminal reads perform no further transport receive");
    check(!test->before_write || a.writes == writes_before, "expired write sends no new transport bytes");
    check(test->terminal || a.transport.socket_fd == -1, "failed operation releases socket immediately");
    if (test->event == FINISHED) check(diagnostic.code == 0 && diagnostic.verify_flags == 0,
                                      "handshake verified before completion check fired");
    if (test->event == CLOSE_NOTIFY) check(diagnostic.code == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY,
                                          "authenticated close decoded before completion check fired");
    tls_stream_read(stream, bytes, sizeof(bytes));
    check(tls_stream_write(stream, (const uint8_t *)"?", 1) < 0 && tls_stream_status(stream) == expected,
          "later I/O cannot resume the closed or failed stream");
    int64_t wall = a.base.now_ms(&a.transport) - started;
    check(wall >= 0 && wall < 2000, "deterministic boundary case completes promptly");
    tls_stream_destroy(stream);
    check(a.closes == 1 && a.transport.socket_fd == -1, "attempted transport closes exactly once");
    vSemaphoreDelete(a.done);
    lwip_transport_destroy(&a.transport);
    printf("RESULT %s status=%d stage=%d code=%d triggers=%u reads=%u writes=%u elapsed=%lu wall_ms=%lld\n",
           test->name, diagnostic.status, diagnostic.stage, diagnostic.code, a.triggers, a.reads, a.writes,
           (unsigned long)a.elapsed, (long long)wall);
}

struct boundary_results boundary_tests(const char *ca)
{
    results = (struct boundary_results){0};
    static const struct test_case cases[] = {
        {"deadline-open", OPENED, EXPIRE, false, false, false},
        {"deadline-before-write", NO_EVENT, EXPIRE, true, false, false},
        {"deadline-after-write", WRITTEN, EXPIRE, false, false, false},
        {"deadline-buffered-read", BUFFERED, EXPIRE, false, false, false},
        {"cancel-buffered-read", BUFFERED, CANCEL, false, false, false},
        {"both-buffered-read", BUFFERED, BOTH, false, false, false},
        {"deadline-close-notify", CLOSE_NOTIFY, EXPIRE, false, false, false},
        {"cancel-close-notify", CLOSE_NOTIFY, CANCEL, false, false, false},
        {"terminal-eof", NO_EVENT, EXPIRE, false, false, true},
        {"cumulative-deadline", NO_EVENT, EXPIRE, false, true, false},
        {"deadline-finished", FINISHED, EXPIRE, false, false, false},
        {"cancel-finished", FINISHED, CANCEL, false, false, false}
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        run_case(ca, &cases[i], (uint16_t)(8473 + i));
    return results;
}
