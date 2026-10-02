#include "security.h"
#include "lwip_transport.h"
#include "FreeRTOS.h"
#include <stdio.h>
#include <string.h>

static struct security_results results;
static void check(bool passed, const char *label)
{
    ++results.checks;
    if (!passed) ++results.failures;
    printf("%s %s\n", passed ? "PASS" : "FAIL", label);
}

static void invalid_date(const char *ca, const char *label, uint16_t number, uint32_t flag)
{
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca) == 0);
    tls_stream_port port = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    int64_t start = port.now_ms(&transport);
    tls_status status = tls_stream_open(stream, "tls.lab.test", number, 3000);
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    int64_t elapsed = port.now_ms(&transport) - start;
    check(status == TLS_ERROR, "date-invalid certificate rejected");
    check(diagnostic.stage == TLS_STAGE_HANDSHAKE, "date rejection occurs in handshake");
    check(diagnostic.verify_flags == flag, "exact certificate date failure flag");
    check(elapsed >= 0 && elapsed < 1250, "date rejection returns promptly");
    uint8_t byte;
    check(tls_stream_read(stream, &byte, 1) < 0, "rejected certificate exposes no application data");
    check(transport.socket_fd == -1, "date rejection releases socket immediately");
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "destroy after date rejection is safe");
    lwip_transport_destroy(&transport);
    printf("RESULT %s status=%d stage=%d verify=%lu elapsed_ms=%lld\n", label, status,
           diagnostic.stage, (unsigned long)diagnostic.verify_flags, (long long)elapsed);
}

static void closure(const char *ca, const char *label, uint16_t number, tls_status expected,
                    bool handshake, const char *prefix)
{
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca) == 0);
    tls_stream_port port = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    int64_t start = port.now_ms(&transport);
    tls_status opened = tls_stream_open(stream, "tls.lab.test", number, 3000);
    check(opened == (handshake ? expected : TLS_OK), "expected closure handshake result");
    size_t received = 0;
    int count = -1;
    uint8_t bytes[32];
    if (!handshake) {
        check(tls_stream_write(stream, (const uint8_t *)"!", 1) == 1, "authenticated request marker sent");
        while (received < sizeof(bytes) && (count = tls_stream_read(stream, bytes + received, sizeof(bytes) - received)) > 0)
            received += (size_t)count;
        check(received == strlen(prefix) && memcmp(bytes, prefix, received) == 0, "only complete authenticated prefix returned");
        check(count < 0, "abrupt close is not successful EOF");
        check(tls_stream_status(stream) == expected, "exact closure failure classification");
    }
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    int64_t elapsed = port.now_ms(&transport) - start;
    check(diagnostic.stage == (handshake ? TLS_STAGE_HANDSHAKE : TLS_STAGE_READ), "expected closure failure phase");
    check(elapsed >= 0 && elapsed < 1250, "closure returns without waiting for deadline");
    check(transport.socket_fd == -1, "abrupt closure releases socket immediately");
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "destroy after closure is safe");
    lwip_transport_destroy(&transport);
    printf("RESULT %s status=%d stage=%d code=%d received=%lu elapsed_ms=%lld\n", label,
           diagnostic.status, diagnostic.stage, diagnostic.code, (unsigned long)received, (long long)elapsed);
}

struct security_results security_tests(const char *ca)
{
    results = (struct security_results){0};
    invalid_date(ca, "expired-certificate", 8456, MBEDTLS_X509_BADCERT_EXPIRED);
    invalid_date(ca, "future-certificate", 8457, MBEDTLS_X509_BADCERT_FUTURE);
    closure(ca, "handshake-eof", 8458, TLS_ERROR, true, "");
    closure(ca, "unclean-eof", 8459, TLS_TRUNCATED, false, "partial");
    closure(ca, "peer-reset", 8460, TLS_TRANSPORT_ERROR, false, "");
    closure(ca, "record-header-cut", 8461, TLS_TRUNCATED, false, "");
    closure(ca, "record-body-cut", 8462, TLS_TRUNCATED, false, "");
    closure(ca, "record-tag-cut", 8463, TLS_TRUNCATED, false, "");
    return results;
}
