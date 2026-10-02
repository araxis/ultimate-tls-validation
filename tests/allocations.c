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
