#include "records.h"
#include "lwip_transport.h"
#include "FreeRTOS.h"
#include <stdio.h>
#include <string.h>

static struct record_results results;
static void check(bool passed, const char *label)
{
    ++results.checks;
    if (!passed) ++results.failures;
    printf("%s %s\n", passed ? "PASS" : "FAIL", label);
}

static void rejection(const char *ca, const char *mode, uint16_t number, int expected_code, bool replay)
{
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca) == 0);
    tls_stream_port port = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    check(tls_stream_open(stream, "tls.lab.test", number, 3000) == TLS_OK, "record case starts with verified handshake");
    check(tls_stream_write(stream, (const uint8_t *)"!", 1) == 1, "record peer receives authenticated marker");
    int64_t start = port.now_ms(&transport);
    uint8_t bytes[32], untouched[32], prefix[64];
    memset(untouched, 0xa5, sizeof(untouched));
    size_t received = 0;
    int count = 0;
    while (received < sizeof(prefix)) {
        memcpy(bytes, untouched, sizeof(bytes));
        count = tls_stream_read(stream, bytes, sizeof(bytes));
        if (count <= 0) break;
        if ((size_t)count > sizeof(prefix) - received) break;
        memcpy(prefix + received, bytes, (size_t)count);
        received += (size_t)count;
    }
    int64_t elapsed = port.now_ms(&transport) - start;
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    check(count < 0 && diagnostic.status == TLS_ERROR, "invalid record returns TLS error rather than EOF");
    check(diagnostic.stage == TLS_STAGE_READ && diagnostic.code == expected_code, "exact record rejection diagnostic");
    check(received == (replay ? 17u : 0u) && (!replay || memcmp(prefix, "authenticated-one", 17) == 0),
          "only the original authenticated record may be returned");
    check(memcmp(bytes, untouched, sizeof(bytes)) == 0, "failed read leaves caller buffer untouched");
    check(elapsed >= 0 && elapsed < 1250, "record rejected without waiting for deadline or peer EOF");
    check(transport.socket_fd == -1, "record rejection closes socket immediately");
    check(tls_stream_read(stream, bytes, sizeof(bytes)) < 0 && memcmp(bytes, untouched, sizeof(bytes)) == 0,
          "read after rejection returns no data");
    check(tls_stream_write(stream, (const uint8_t *)"?", 1) < 0, "write after rejection is refused");
    tls_stream_diagnostics after = tls_stream_diagnostic(stream);
    check(after.status == diagnostic.status && after.stage == diagnostic.stage && after.code == diagnostic.code,
          "rejection diagnostic survives subsequent calls");
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "destroy after record rejection is safe");
    lwip_transport_destroy(&transport);
    printf("RESULT record-%s status=%d stage=%d code=%d received=%lu elapsed_ms=%lld\n", mode,
           diagnostic.status, diagnostic.stage, diagnostic.code, (unsigned long)received, (long long)elapsed);
}

struct record_results record_tests(const char *ca)
{
    results = (struct record_results){0};
    static const struct { const char *mode; int code; bool replay; } cases[] = {
        {"type", MBEDTLS_ERR_SSL_INVALID_RECORD, false},
        {"version", MBEDTLS_ERR_SSL_INVALID_RECORD, false},
        {"empty", MBEDTLS_ERR_SSL_INVALID_RECORD, false},
        /* The pinned dependency rejects reads larger than its input buffer
         * in mbedtls_ssl_fetch_input(), before attempting a body read. */
        {"oversized", MBEDTLS_ERR_SSL_BAD_INPUT_DATA, false},
        {"nonce", MBEDTLS_ERR_SSL_INVALID_MAC, false},
        {"ciphertext", MBEDTLS_ERR_SSL_INVALID_MAC, false},
        {"tag", MBEDTLS_ERR_SSL_INVALID_MAC, false},
        {"replay", MBEDTLS_ERR_SSL_INVALID_MAC, true}
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        rejection(ca, cases[i].mode, (uint16_t)(8465 + i), cases[i].code, cases[i].replay);
    return results;
}
