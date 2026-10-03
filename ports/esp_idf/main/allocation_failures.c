#include "allocation_failures.h"
#include "allocation_meter.h"
#include "authentication.h"
#include "resource_probe.h"
#include "transport.h"
#include "fixture.h"
#include <stdio.h>

/* The port context is unchanged. Only this fixture's open callback arms failure
 * after a successful TCP connection, before the first handshake allocation. */
static int fail_after_connect(void *context, const char *host, uint16_t port, uint32_t budget)
{
    tls_stream_port original = idf_transport_port(context);
    int result = original.open(context, host, port, budget);
    if (!result) allocation_meter_fail_after(0);
    return result;
}

static void failure(unsigned index, unsigned point, bool ready, SemaphoreHandle_t done,
                    void (*check)(bool, const char *))
{
    static const char *labels[] = {"create", "setup", "handshake"};
    printf("ATTEMPT allocation-%u-%s\n", index, labels[point]);
    allocation_meter_begin();
    resource_snapshot(index, "before", done, check);
    idf_transport transport;
    int loaded = idf_transport_init(&transport, lab_root, sizeof(lab_root));
    check(loaded == 0, "trust loaded before allocation injection");
    transport.clock_ready = ready;
    tls_stream_port port = idf_transport_port(&transport);
    if (point == 2) port.open = fail_after_connect;
    if (point == 0) allocation_meter_fail_after(0);
    tls_stream *stream = tls_stream_create(&port);
    check((stream == NULL) == (point == 0), "expected stream allocation outcome");
    if (point == 1) allocation_meter_fail_after(0);
    tls_status status = TLS_INVALID_ARGUMENT;
    if (stream && ready && !loaded) status = tls_stream_open(stream, "192.0.2.1", 8443, 5000);
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    check(status == (point ? TLS_ERROR : TLS_INVALID_ARGUMENT) && diagnostic.status == status &&
          diagnostic.stage == (point == 0 ? TLS_STAGE_VALIDATE : point == 1 ? TLS_STAGE_SETUP : TLS_STAGE_HANDSHAKE) &&
          diagnostic.code == (point ? MBEDTLS_ERR_SSL_ALLOC_FAILED : 0) &&
          diagnostic.verify_flags == (point == 2 ? UINT32_MAX : 0), "exact allocation failure diagnostic");
    allocation_totals totals = allocation_meter_read();
    check(totals.rejected == 1 && totals.rejected_bytes > 0, "exactly one allocation rejected");
    check(transport.open_calls == (point == 2 ? 1u : 0u), "expected network reachability");
    check(transport.socket_fd == -1, "failure closed socket");
    uint8_t byte = 0xa5;
    check(tls_stream_read(stream, &byte, 1) == -1 && byte == 0xa5, "failed read leaves caller output unchanged");
    check(tls_stream_write(stream, &byte, 1) == -1, "failed write refused");
    tls_stream_diagnostics after = tls_stream_diagnostic(stream);
    check(after.status == diagnostic.status && after.stage == diagnostic.stage &&
          after.code == diagnostic.code && after.verify_flags == diagnostic.verify_flags, "failure diagnostic stable");
    printf("ALLOCATION_RESULT index=%u point=%u status=%d stage=%d code=%d verify=%lu rejected=%u bytes=%zu opens=%u\n",
           index, point, status, diagnostic.stage, diagnostic.code, (unsigned long)diagnostic.verify_flags,
           totals.rejected, totals.rejected_bytes, transport.open_calls);
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
        for (unsigned point = 0; point < 3; ++point) {
            unsigned index = round * 3 + point + 1;
            failure(index, point, ready, done, check);
            recovery(index, ready, done, check);
        }
        resource_cooldown(round + 1, done, check);
    }
    vSemaphoreDelete(done);
}
