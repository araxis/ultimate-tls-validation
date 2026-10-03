#include "security.h"
#include "authentication.h"
#include "transport.h"
#include "fixture.h"
#include "lwip_dns.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcp_priv.h"
#include "esp_timer.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *label;
    uint16_t port;
    tls_status status;
    tls_stage stage;
    int code;
    uint32_t flags;
    const char *prefix;
} security_case;

static void run_case(const security_case *test, bool ready, void (*check)(bool, const char *))
{
    printf("ATTEMPT %s\n", test->label);
    idf_transport transport;
    int loaded = idf_transport_init(&transport, lab_root, sizeof(lab_root));
    check(loaded == 0, "security trust loaded");
    transport.clock_ready = ready;
    tls_stream_port port = idf_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    check(stream != NULL, "security stream created");
    int64_t start = port.now_ms(&transport);
    tls_status opened = TLS_INVALID_ARGUMENT;
    if (ready && !loaded && stream) opened = tls_stream_open(stream, "192.0.2.1", test->port, 3000);
    bool established = test->stage == TLS_STAGE_READ;
    check(opened == (established ? TLS_OK : test->status), "expected security open result");
    uint8_t bytes[32];
    size_t received = 0;
    int count = -1;
    if (established) {
        check(tls_stream_write(stream, (const uint8_t *)"!", 1) == 1, "authenticated closure marker sent");
        while (received < sizeof(bytes) &&
               (count = tls_stream_read(stream, bytes + received, sizeof(bytes) - received)) > 0)
            received += (size_t)count;
        check(count < 0 && received == strlen(test->prefix) && !memcmp(bytes, test->prefix, received),
              "only authenticated prefix returned before failure");
    }
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    int64_t elapsed = port.now_ms(&transport) - start;
    check(diagnostic.status == test->status && diagnostic.stage == test->stage &&
          diagnostic.code == test->code && diagnostic.verify_flags == test->flags,
          "exact security failure diagnostic");
    check(elapsed >= 0 && elapsed <= 3250, "security failure within operation budget");
    check(transport.open_calls == 1 && transport.socket_fd == -1, "security failure releases opened socket");
    uint8_t sentinel = 0xa5;
    check(tls_stream_read(stream, &sentinel, 1) == -1 && sentinel == 0xa5,
          "terminal security read preserves output");
    check(tls_stream_write(stream, &sentinel, 1) == -1, "terminal security write refused");
    tls_stream_diagnostics after = tls_stream_diagnostic(stream);
    check(after.status == diagnostic.status && after.stage == diagnostic.stage &&
          after.code == diagnostic.code && after.verify_flags == diagnostic.verify_flags,
          "security diagnostic remains stable");
    printf("SECURITY_RESULT %s status=%d stage=%d code=%d verify=%lu received=%zu opens=%u elapsed=%lld\n",
           test->label, diagnostic.status, diagnostic.stage, diagnostic.code,
           (unsigned long)diagnostic.verify_flags, received, transport.open_calls, (long long)elapsed);
    tls_stream_destroy(stream);
    idf_transport_destroy(&transport);
    check(transport.socket_fd == -1, "security destruction leaves socket released");
}

typedef struct { SemaphoreHandle_t done; unsigned active, timewait; } network_state;

static void capture(void *argument)
{
    network_state *state = argument;
    for (struct tcp_pcb *p = tcp_active_pcbs; p; p = p->next) ++state->active;
    for (struct tcp_pcb *p = tcp_tw_pcbs; p; p = p->next) ++state->timewait;
    xSemaphoreGive(state->done);
}

static void cooldown(void (*check)(bool, const char *))
{
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    configASSERT(done);
    int64_t start = esp_timer_get_time();
    network_state state;
    do {
        state = (network_state){.done = done};
        configASSERT(tcpip_callback(capture, &state) == ERR_OK);
        configASSERT(xSemaphoreTake(done, pdMS_TO_TICKS(1000)) == pdTRUE);
        if (!state.active && !state.timewait) break;
        vTaskDelay(pdMS_TO_TICKS(2000));
    } while (esp_timer_get_time() - start < 135000000LL);
    unsigned pending = lwip_dns_pending();
    check(!state.active && !state.timewait && !pending, "security network state drained naturally");
    printf("SECURITY_CLEANUP active=%u timewait=%u dns=%u elapsed=%lld\n",
           state.active, state.timewait, pending, (long long)((esp_timer_get_time() - start) / 1000));
    vSemaphoreDelete(done);
}

void security_probe(bool ready, void (*check)(bool, const char *))
{
    static const security_case cases[] = {
        {"expired", 8456, TLS_ERROR, TLS_STAGE_HANDSHAKE, MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,
         MBEDTLS_X509_BADCERT_EXPIRED, ""},
        {"future", 8457, TLS_ERROR, TLS_STAGE_HANDSHAKE, MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,
         MBEDTLS_X509_BADCERT_FUTURE, ""},
        {"handshake-eof", 8458, TLS_ERROR, TLS_STAGE_HANDSHAKE, MBEDTLS_ERR_SSL_CONN_EOF, UINT32_MAX, ""},
        {"unclean-eof", 8459, TLS_TRUNCATED, TLS_STAGE_READ, 0, 0, "partial"},
        {"peer-reset", 8460, TLS_TRANSPORT_ERROR, TLS_STAGE_READ, MBEDTLS_ERR_SSL_INTERNAL_ERROR, 0, ""}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        run_case(&cases[i], ready, check);
        char label[64];
        snprintf(label, sizeof(label), "recovery-%s", cases[i].label);
        authentication_recovery(label, ready, check);
    }
    cooldown(check);
}
