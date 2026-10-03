#include "allocation_failures.h"
#include "allocation_meter.h"
#include "authentication.h"
#include "resource_probe.h"
#include "transport.h"
#include "fixture.h"
#include <stdio.h>

typedef struct {
    const char *label;
    tls_stage stage;
    size_t allowed;
    int code;
} allocation_case;

static const allocation_case cases[] = {
    {"create", TLS_STAGE_VALIDATE, 0, 0},
    {"setup", TLS_STAGE_SETUP, 0, MBEDTLS_ERR_SSL_ALLOC_FAILED},
    {"handshake", TLS_STAGE_HANDSHAKE, 0, MBEDTLS_ERR_SSL_ALLOC_FAILED},
    {"setup-output", TLS_STAGE_SETUP, 1, MBEDTLS_ERR_SSL_ALLOC_FAILED},
    {"setup-state", TLS_STAGE_SETUP, 2, MBEDTLS_ERR_SSL_ALLOC_FAILED},
    {"certificate-copy", TLS_STAGE_HANDSHAKE, 1, MBEDTLS_ERR_X509_ALLOC_FAILED}
};

/* Decorate only the fixture's open callback; retain the original context. */
static int open_then_fail(void *context, const char *host, uint16_t port, uint32_t budget, size_t allowed)
{
    tls_stream_port original = idf_transport_port(context);
    int result = original.open(context, host, port, budget);
    if (!result) allocation_meter_fail_after(allowed);
    return result;
}

static int fail_after_connect(void *context, const char *host, uint16_t port, uint32_t budget)
{
    return open_then_fail(context, host, port, budget, 0);
}

static int fail_after_certificate(void *context, const char *host, uint16_t port, uint32_t budget)
{
    return open_then_fail(context, host, port, budget, 1);
}

static void failure(unsigned index, unsigned point, bool ready, SemaphoreHandle_t done,
                    void (*check)(bool, const char *))
{
    const allocation_case *test = &cases[point];
    bool creation = test->stage == TLS_STAGE_VALIDATE;
    bool handshake = test->stage == TLS_STAGE_HANDSHAKE;
    printf("ATTEMPT allocation-%u-%s\n", index, test->label);
    allocation_meter_begin();
    resource_snapshot(index, "before", done, check);
    idf_transport transport;
    int loaded = idf_transport_init(&transport, lab_root, sizeof(lab_root));
    check(loaded == 0, "trust loaded before allocation injection");
    transport.clock_ready = ready;
    tls_stream_port port = idf_transport_port(&transport);
    if (handshake) port.open = test->allowed ? fail_after_certificate : fail_after_connect;
    if (creation) allocation_meter_fail_after(test->allowed);
    tls_stream *stream = tls_stream_create(&port);
    check((stream == NULL) == creation, "expected stream allocation outcome");
    if (test->stage == TLS_STAGE_SETUP) allocation_meter_fail_after(test->allowed);
    tls_status status = TLS_INVALID_ARGUMENT;
    if (stream && ready && !loaded) status = tls_stream_open(stream, "192.0.2.1", 8443, 5000);
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    check(status == (creation ? TLS_INVALID_ARGUMENT : TLS_ERROR) && diagnostic.status == status &&
          diagnostic.stage == test->stage && diagnostic.code == test->code &&
          diagnostic.verify_flags == (handshake ? UINT32_MAX : 0), "exact allocation failure diagnostic");
    allocation_totals totals = allocation_meter_read();
    check(totals.rejected == 1 && totals.rejected_bytes > 0, "exactly one allocation rejected");
    check(totals.rejected_prior == test->allowed &&
          (test->allowed ? totals.rejected_live_bytes > totals.injection_base_bytes :
                           totals.rejected_live_bytes == totals.injection_base_bytes),
          "expected allocations owned at failure boundary");
    check(transport.open_calls == (handshake ? 1u : 0u), "expected network reachability");
    check(transport.socket_fd == -1, "failure closed socket");
    uint8_t byte = 0xa5;
    check(tls_stream_read(stream, &byte, 1) == -1 && byte == 0xa5, "failed read leaves caller output unchanged");
    check(tls_stream_write(stream, &byte, 1) == -1, "failed write refused");
    tls_stream_diagnostics after = tls_stream_diagnostic(stream);
    check(after.status == diagnostic.status && after.stage == diagnostic.stage &&
          after.code == diagnostic.code && after.verify_flags == diagnostic.verify_flags, "failure diagnostic stable");
    printf("ALLOCATION_RESULT index=%u point=%u status=%d stage=%d code=%d verify=%lu rejected=%u bytes=%zu opens=%u prior=%u base=%zu live_at_failure=%zu\n",
           index, point, status, diagnostic.stage, diagnostic.code, (unsigned long)diagnostic.verify_flags,
           totals.rejected, totals.rejected_bytes, transport.open_calls, totals.rejected_prior,
           totals.injection_base_bytes, totals.rejected_live_bytes);
    tls_stream_destroy(stream);
    idf_transport_destroy(&transport);
    resource_snapshot(index, "settled", done, check);
    allocation_meter_end();
}

static void recovery(unsigned index, bool ready, SemaphoreHandle_t done, void (*check)(bool, const char *))
{
    char label[40];
    snprintf(label, sizeof(label), "allocation-recovery-%u", index);
    allocation_meter_begin();
    authentication_recovery(label, ready, check);
    check(allocation_meter_read().rejected == 0, "recovery has no allocation injection");
    resource_snapshot(index, "settled", done, check);
    allocation_meter_end();
}

void allocation_failures_probe(bool ready, void (*check)(bool, const char *))
{
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    configASSERT(done);
    recovery(0, ready, done, check);
    resource_cooldown(0, done, check);
    for (unsigned round = 0; round < 2; ++round) {
        for (unsigned point = 0; point < sizeof(cases) / sizeof(cases[0]); ++point) {
            unsigned index = round * (sizeof(cases) / sizeof(cases[0])) + point + 1;
            failure(index, point, ready, done, check);
            recovery(index, ready, done, check);
        }
        resource_cooldown(round + 1, done, check);
    }
    vSemaphoreDelete(done);
}
