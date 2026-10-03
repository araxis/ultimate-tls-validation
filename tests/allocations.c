#include "allocations.h"
#include "lwip_transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* GNU link wrappers affect only direct calls in the linked test objects.
 * POSIX FreeRTOS tasks have separate threads; injection is private to this
 * caller, never the TCP/IP or scheduler threads. No allocator is replaced. */
void *__real_calloc(size_t count, size_t size);
void __real_free(void *pointer);
static _Thread_local struct {
    bool enabled;
    unsigned attempts, fail_at, injected, live;
    size_t bytes, peak;
    struct { void *pointer; size_t bytes; } slots[256];
} allocation;

void allocation_measure_begin(void)
{
    if (allocation.enabled) abort();
    memset(&allocation, 0, sizeof(allocation));
    allocation.enabled = true;
}

struct allocation_measurement allocation_measure_read(void)
{
    return (struct allocation_measurement){allocation.live, allocation.bytes, allocation.peak};
}

struct allocation_measurement allocation_measure_end(void)
{
    if (!allocation.enabled) abort();
    allocation.enabled = false;
    return allocation_measure_read();
}

void *__wrap_calloc(size_t count, size_t size)
{
    if (!allocation.enabled) return __real_calloc(count, size);
    if (++allocation.attempts == allocation.fail_at) {
        ++allocation.injected;
        return NULL;
    }
    void *pointer = __real_calloc(count, size);
    if (!pointer) return NULL;
    for (unsigned i = 0; i < 256; ++i) {
        if (!allocation.slots[i].pointer) {
            allocation.slots[i].pointer = pointer;
            allocation.slots[i].bytes = count * size;
            ++allocation.live;
            allocation.bytes += count * size;
            if (allocation.bytes > allocation.peak) allocation.peak = allocation.bytes;
            return pointer;
        }
    }
    abort(); /* Tracking exhaustion must never masquerade as a clean run. */
}

void __wrap_free(void *pointer)
{
    if (allocation.enabled && pointer) {
        for (unsigned i = 0; i < 256; ++i) {
            if (allocation.slots[i].pointer == pointer) {
                allocation.bytes -= allocation.slots[i].bytes;
                --allocation.live;
                allocation.slots[i].pointer = NULL;
                break;
            }
        }
    }
    __real_free(pointer);
}

static int stop_before_network(void *context, const char *host, uint16_t port, uint32_t budget)
{
    (void)context; (void)host; (void)port; (void)budget;
    return -1;
}

static struct allocation_results results;
static void check(bool passed, const char *label)
{
    ++results.checks;
    if (!passed) ++results.failures;
    printf("%s %s\n", passed ? "PASS" : "FAIL", label);
}

static unsigned attempt(const char *ca, unsigned fail_at)
{
    memset(&allocation, 0, sizeof(allocation));
    allocation.enabled = true;
    allocation.fail_at = fail_at;
    lwip_transport transport;
    int roots = lwip_transport_init(&transport, ca);
    tls_stream *stream = NULL;
    tls_status status = TLS_ERROR;
    tls_stage stage = TLS_STAGE_VALIDATE;
    if (roots == 0) {
        tls_stream_port port = lwip_transport_port(&transport);
        port.open = stop_before_network;
        stream = tls_stream_create(&port);
        if (stream) {
            status = tls_stream_open(stream, "tls.lab.test", 8443, 3000);
            stage = tls_stream_diagnostic(stream).stage;
        }
    }
    bool created = stream != NULL;
    tls_stream_destroy(stream);
    lwip_transport_destroy(&transport);
    allocation.enabled = false;
    check(fail_at ? allocation.injected == 1 : allocation.attempts > 0, "allocation injection accounted");
    check(fail_at ? roots != 0 || !created || status == TLS_ERROR :
          roots == 0 && created && status == TLS_TRANSPORT_ERROR && stage == TLS_STAGE_TCP_OPEN,
          "allocation outcome matches pre-network scope");
    check(allocation.live == 0 && allocation.bytes == 0, "all tracked allocations freed");
    check(transport.socket_fd == -1, "allocation case never leaves a socket");
    printf("RESULT allocation-case index=%u attempts=%u injected=%u live=%u bytes=%lu peak=%lu stage=%d status=%d\n",
           fail_at, allocation.attempts, allocation.injected, allocation.live,
           (unsigned long)allocation.bytes, (unsigned long)allocation.peak, stage, status);
    return allocation.attempts;
}

struct allocation_results allocation_tests(const char *ca)
{
    results = (struct allocation_results){0};
    unsigned sites = attempt(ca, 0);
    if (sites == 0 || sites > 128) abort();
    printf("ALLOCATIONS sites=%u\n", sites);
    for (unsigned i = 1; i <= sites; ++i) attempt(ca, i);
    check(attempt(ca, 0) == sites, "allocation path recovers after failure sweep");
    return results;
}

/* Arm only after the real TCP open. Retain setup pointers in the accounting,
 * but number the injected calls from the first handshake allocation. */
static _Thread_local struct {
    int (*open)(void *, const char *, uint16_t, uint32_t);
    unsigned fail_at, start;
    bool armed;
} handshake;

static int arm_handshake(void *context, const char *host, uint16_t port, uint32_t budget)
{
    int status = handshake.open(context, host, port, budget);
    if (status == 0) {
        handshake.start = allocation.attempts;
        allocation.fail_at = handshake.fail_at ? handshake.start + handshake.fail_at : 0;
        handshake.armed = true;
    }
    return status;
}

static unsigned handshake_attempt(const char *ca, unsigned fail_at)
{
    memset(&allocation, 0, sizeof(allocation));
    memset(&handshake, 0, sizeof(handshake));
    allocation.enabled = true;
    handshake.fail_at = fail_at;
    lwip_transport transport;
    int roots = lwip_transport_init(&transport, ca);
    tls_stream_port port = lwip_transport_port(&transport);
    handshake.open = port.open;
    port.open = arm_handshake;
    tls_stream *stream = roots == 0 ? tls_stream_create(&port) : NULL;
    int64_t start = port.now_ms(&transport);
    tls_status status = tls_stream_open(stream, "tls.lab.test", 8464, 3000);
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    unsigned attempts = handshake.armed ? allocation.attempts - handshake.start : 0;
    unsigned open_live = allocation.live;
    size_t open_bytes = allocation.bytes;
    /* Application I/O is measured but is outside the injection window. */
    allocation.fail_at = 0;
    bool exchange = false;
    if (status == TLS_OK) {
        uint8_t byte = 'K';
        exchange = tls_stream_write(stream, &byte, 1) == 1 &&
                   tls_stream_read(stream, &byte, 1) == 1 && byte == 'Y' &&
                   tls_stream_read(stream, &byte, 1) == 0 && tls_stream_status(stream) == TLS_OK;
    }
    int64_t elapsed = port.now_ms(&transport) - start;
    check(handshake.armed && roots == 0 && stream, "handshake allocation test reaches real TCP connection");
    check(fail_at ? allocation.injected == 1 : allocation.injected == 0 && attempts > 0,
          "handshake allocation injection reached exactly once");
    check(diagnostic.stage == TLS_STAGE_HANDSHAKE &&
          (fail_at ? status == TLS_ERROR : status == TLS_OK && exchange),
          "handshake allocation outcome matches injection");
    check(status == TLS_OK || transport.socket_fd == -1, "failed handshake closes socket immediately");
    check(elapsed >= 0 && elapsed <= 3250, "handshake allocation attempt stays bounded");
    tls_stream_destroy(stream);
    lwip_transport_destroy(&transport);
    allocation.enabled = false;
    check(allocation.live == 0 && allocation.bytes == 0, "handshake allocations all freed after destruction");
    check(transport.socket_fd == -1, "handshake allocation socket released after destruction");
    printf("RESULT handshake-allocation index=%u attempts=%u injected=%u open_live=%u open_bytes=%lu live=%u bytes=%lu peak=%lu stage=%d status=%d code=%d elapsed_ms=%lld\n",
           fail_at, attempts, allocation.injected, open_live, (unsigned long)open_bytes, allocation.live,
           (unsigned long)allocation.bytes, (unsigned long)allocation.peak,
           diagnostic.stage, status, diagnostic.code, (long long)elapsed);
    return attempts;
}

struct allocation_results handshake_allocation_tests(const char *ca)
{
    results = (struct allocation_results){0};
    unsigned sites = handshake_attempt(ca, 0);
    if (sites == 0 || sites > 100000) abort();
    printf("HANDSHAKE_ALLOCATIONS sites=%u\n", sites);
    /* Sample the first 16, last 8 and 16 evenly spaced later call ordinals.
     * At most 39 injected attempts; these are not source allocation sites. */
    for (unsigned index = 1; index <= sites; ++index) {
        bool selected = index <= 16 || sites - index < 8;
        for (unsigned i = 1; !selected && sites > 16 && i <= 16; ++i)
            selected = index == 16 + (sites - 16) * i / 16;
        if (selected) handshake_attempt(ca, index);
    }
    handshake_attempt(ca, 0);
    return results;
}
