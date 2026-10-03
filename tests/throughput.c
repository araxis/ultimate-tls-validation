#include "throughput.h"
#include "lwip_transport.h"
#include "FreeRTOS.h"
#include <inttypes.h>
#include <stdio.h>
#include <time.h>

enum { PAYLOAD_BYTES = 2 * 1024 * 1024, CASES = 8 };

static uint64_t nanoseconds(clockid_t clock)
{
    struct timespec now;
    int result = clock_gettime(clock, &now);
    configASSERT(result == 0);
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static void check(struct throughput_results *r, bool passed, const char *label)
{
    ++r->checks;
    if (!passed) ++r->failures;
    printf("%s throughput: %s\n", passed ? "PASS" : "FAIL", label);
}

struct throughput_results throughput_tests(const char *ca_path)
{
    struct throughput_results result = {0};
    for (unsigned index = 0; index < CASES; ++index) {
        lwip_transport transport;
        configASSERT(lwip_transport_init(&transport, ca_path) == 0);
        tls_stream_port callbacks = lwip_transport_port(&transport);
        tls_stream *stream = tls_stream_create(&callbacks);
        configASSERT(stream);
        check(&result, tls_stream_open(stream, "tls.lab.test", 8476, 15000) == TLS_OK,
              "verified handshake");
        uint8_t trigger = (uint8_t)index;
        check(&result, tls_stream_write(stream, &trigger, 1) == 1, "start request sent");
        uint8_t buffer[512];
        size_t total = 0, calls = 0, chunk = index % 2 ? 512 : 64;
        bool exact = true;
        uint64_t wall = nanoseconds(CLOCK_MONOTONIC);
        uint64_t cpu = nanoseconds(CLOCK_THREAD_CPUTIME_ID);
        int count;
        while ((count = tls_stream_read(stream, buffer, chunk)) > 0) {
            ++calls;
            for (int offset = 0; offset < count; ++offset) {
                uint8_t expected = (uint8_t)((total + (size_t)offset) * 37U + 11U);
                if (buffer[offset] != expected) exact = false;
            }
            total += (size_t)count;
            if (total > PAYLOAD_BYTES) break;
        }
        cpu = nanoseconds(CLOCK_THREAD_CPUTIME_ID) - cpu;
        wall = nanoseconds(CLOCK_MONOTONIC) - wall;
        check(&result, exact && total == PAYLOAD_BYTES, "complete exact binary payload");
        check(&result, count == 0 && tls_stream_status(stream) == TLS_OK, "authenticated EOF");
        check(&result, cpu > 0 && wall > 0, "positive clock measurements");
        tls_stream_destroy(stream);
        check(&result, transport.socket_fd == -1, "transport released");
        lwip_transport_destroy(&transport);
        printf("RESULT throughput index=%u chunk=%zu warmup=%u bytes=%zu calls=%zu wall_ns=%" PRIu64
               " cpu_ns=%" PRIu64 "\n", index, chunk, index < 2, total, calls, wall, cpu);
    }
    return result;
}
