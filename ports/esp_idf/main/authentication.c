#include "authentication.h"
#include "transport.h"
#include "fixture.h"
#include "mbedtls/ctr_drbg.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *label;
    uint16_t port;
    tls_status status;
    tls_stage stage;
    int code;
    uint32_t flags;
} authentication_case;

static int fail_entropy(void *context, unsigned char *bytes, size_t length)
{
    (void)context;
    (void)bytes;
    (void)length;
    return -1;
}

static void run_case(const authentication_case *test, bool ready,
                     void (*check)(bool, const char *))
{
    printf("ATTEMPT %s\n", test->label);
    idf_transport transport;
    int loaded = idf_transport_init(&transport, lab_root, sizeof(lab_root));
    check(loaded == 0, "fixture trust anchor loaded");
    transport.clock_ready = ready && test->status != TLS_TIME_UNAVAILABLE;
    tls_stream_port port = idf_transport_port(&transport);
    if (test->stage == TLS_STAGE_RANDOM) port.entropy = fail_entropy;
    tls_stream *stream = tls_stream_create(&port);
    check(stream != NULL, "stream allocated");
    tls_status status = TLS_INVALID_ARGUMENT;
    if (ready && !loaded && stream) status = tls_stream_open(stream, "192.0.2.1", test->port, 15000);
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    check(status == test->status && diagnostic.status == test->status &&
          diagnostic.stage == test->stage && diagnostic.code == test->code &&
          diagnostic.verify_flags == test->flags, "exact open diagnostic");
    bool before_network = test->stage == TLS_STAGE_TIME || test->stage == TLS_STAGE_RANDOM;
    check(transport.open_calls == (before_network ? 0u : 1u), "expected transport open count");
    size_t sent = 0, received = 0;
    if (test->status == TLS_OK) {
        static const uint8_t request[] = "GET /probe HTTP/1.1\r\nHost: tls.lab.test\r\nConnection: close\r\n\r\n";
        static const uint8_t expected[] = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n"
#if LAB_ECDSA
            "\x00\xff\x80\r\nA\x00\n";
#else
            "lwip-ok\n";
#endif
        uint8_t response[256];
        int count = -1;
        if (status == TLS_OK) {
            while (sent < sizeof(request) - 1) {
                count = tls_stream_write(stream, request + sent, sizeof(request) - 1 - sent);
                if (count <= 0) break;
                sent += (size_t)count;
            }
            while (received < sizeof(response) &&
                   (count = tls_stream_read(stream, response + received, sizeof(response) - received)) > 0)
                received += (size_t)count;
        }
        check(sent == sizeof(request) - 1, "complete request written");
        check(received == sizeof(expected) - 1 && memcmp(response, expected, received) == 0,
              "exact response bytes");
        check(count == 0 && tls_stream_status(stream) == TLS_OK, "authenticated EOF");
    } else {
        check(transport.socket_fd == -1, "failed open released socket");
        uint8_t output[8], sentinel[8];
        memset(output, 0xa5, sizeof(output));
        memcpy(sentinel, output, sizeof(output));
        check(tls_stream_read(stream, output, sizeof(output)) == -1, "read refused after rejection");
        check(tls_stream_write(stream, sentinel, sizeof(sentinel)) == -1, "write refused after rejection");
        check(memcmp(output, sentinel, sizeof(output)) == 0, "rejected read preserved output");
        tls_stream_diagnostics after = tls_stream_diagnostic(stream);
        check(after.status == diagnostic.status && after.stage == diagnostic.stage &&
              after.code == diagnostic.code && after.verify_flags == diagnostic.verify_flags,
              "rejection diagnostic remains stable");
    }
    diagnostic = tls_stream_diagnostic(stream);
    printf("RESULT %s status=%d stage=%d code=%d verify=%lu sent=%zu received=%zu opens=%u\n",
           test->label, diagnostic.status, diagnostic.stage, diagnostic.code,
           (unsigned long)diagnostic.verify_flags, sent, received, transport.open_calls);
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "socket released after destroy");
    idf_transport_destroy(&transport);
}

void authentication_recovery(const char *label, bool ready, void (*check)(bool, const char *))
{
    const authentication_case test = {label, 8443, TLS_OK, TLS_STAGE_HANDSHAKE, 0, 0};
    run_case(&test, ready, check);
}

void authentication_probe(bool ready, void (*check)(bool, const char *))
{
    static const authentication_case cases[] = {
        {"valid-chain", 8443, TLS_OK, TLS_STAGE_HANDSHAKE, 0, 0},
        {"wrong-host", 8444, TLS_ERROR, TLS_STAGE_HANDSHAKE,
         MBEDTLS_ERR_X509_CERT_VERIFY_FAILED, MBEDTLS_X509_BADCERT_CN_MISMATCH},
        {"recovery-after-host", 8443, TLS_OK, TLS_STAGE_HANDSHAKE, 0, 0},
        {"wrong-root", 8445, TLS_ERROR, TLS_STAGE_HANDSHAKE,
         MBEDTLS_ERR_X509_CERT_VERIFY_FAILED, MBEDTLS_X509_BADCERT_NOT_TRUSTED},
        {"recovery-after-root", 8443, TLS_OK, TLS_STAGE_HANDSHAKE, 0, 0},
        {"missing-time", 8443, TLS_TIME_UNAVAILABLE, TLS_STAGE_TIME, 0, 0},
        {"recovery-after-time", 8443, TLS_OK, TLS_STAGE_HANDSHAKE, 0, 0},
        {"entropy-failure", 8443, TLS_ERROR, TLS_STAGE_RANDOM,
         MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED, 0},
        {"recovery-after-entropy", 8443, TLS_OK, TLS_STAGE_HANDSHAKE, 0, 0}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        run_case(&cases[i], ready, check);
}
