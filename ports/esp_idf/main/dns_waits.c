#include "dns_waits.h"
#include "authentication.h"
#include "transport.h"
#include "lwip_dns.h"
#include "fixture.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/dns.h"
#include "lwip/tcpip.h"
#include <stdio.h>
#include <string.h>

static int64_t now_ms(void) { return esp_timer_get_time() / 1000; }

static void configure_dns(void *argument)
{
    ip_addr_t server;
    IP_ADDR4(&server, 192, 0, 2, 1);
    dns_setserver(0, &server);
    xSemaphoreGive((SemaphoreHandle_t)argument);
}

static bool drain_lookups(void)
{
    int64_t end = now_ms() + 3500;
    while (lwip_dns_pending() && now_ms() < end) vTaskDelay(1);
    return lwip_dns_pending() == 0;
}

typedef struct {
    idf_transport *transport;
    SemaphoreHandle_t done;
    int64_t fired;
    bool observed;
} cancellation;

static void cancel_lookup(void *argument)
{
    cancellation *cancel = argument;
    int64_t end = now_ms() + 1000;
    while (!lwip_dns_pending() && now_ms() < end) vTaskDelay(1);
    cancel->observed = lwip_dns_pending() == 1;
    vTaskDelay(pdMS_TO_TICKS(50));
    cancel->fired = now_ms();
    atomic_store(&cancel->transport->cancel_requested, true);
    xSemaphoreGive(cancel->done);
    vTaskDelete(NULL);
}

typedef struct {
    const char *label, *host;
    uint16_t port;
    uint32_t budget, minimum, maximum;
    tls_status status;
    tls_stage stage;
    int code;
    uint32_t flags;
    unsigned pending;
} dns_case;

static void failure_case(const dns_case *test, bool ready,
                         void (*check)(bool, const char *))
{
    printf("ATTEMPT %s\n", test->label);
    idf_transport transport;
    check(idf_transport_init(&transport, lab_root, sizeof(lab_root)) == 0, "fixture trust loaded");
    transport.clock_ready = ready;
    tls_stream_port port = idf_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    check(stream != NULL, "DNS stream allocated");
    cancellation cancel = {.transport = &transport, .done = xSemaphoreCreateBinary()};
    configASSERT(cancel.done);
    TaskHandle_t worker = NULL;
    bool cancelling = test->status == TLS_CANCELLED;
    if (cancelling) configASSERT(xTaskCreate(cancel_lookup, "dns-cancel", 2048, &cancel, 2, &worker) == pdPASS);
    int64_t start = now_ms();
    tls_status status = tls_stream_open(stream, test->host, test->port, test->budget);
    int64_t end = now_ms();
    if (worker) configASSERT(xSemaphoreTake(cancel.done, pdMS_TO_TICKS(1500)) == pdTRUE);
    vSemaphoreDelete(cancel.done);
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    check(status == test->status && diagnostic.status == test->status && diagnostic.stage == test->stage &&
          diagnostic.code == test->code && diagnostic.verify_flags == test->flags, "exact DNS failure diagnostic");
    int64_t elapsed = end - start;
    check(elapsed >= test->minimum && elapsed <= test->maximum && (!cancelling ||
          (cancel.observed && cancel.fired <= end && end - cancel.fired <= 250)), "bounded DNS result");
    check(atomic_load(&transport.cancel_requested) == cancelling, "expected DNS cancellation signal");
    check(transport.socket_fd == -1, "DNS failure released socket");
    uint8_t bytes[8], sentinel[8];
    memset(bytes, 0xa5, sizeof(bytes));
    memcpy(sentinel, bytes, sizeof(bytes));
    check(tls_stream_read(stream, bytes, sizeof(bytes)) == -1, "DNS terminal read refused");
    check(tls_stream_write(stream, sentinel, sizeof(sentinel)) == -1, "DNS terminal write refused");
    check(memcmp(bytes, sentinel, sizeof(bytes)) == 0, "DNS terminal output unchanged");
    tls_stream_diagnostics after = tls_stream_diagnostic(stream);
    check(after.status == diagnostic.status && after.stage == diagnostic.stage &&
          after.code == diagnostic.code && after.verify_flags == diagnostic.verify_flags, "DNS diagnostic stable");
    check(transport.open_calls == 1, "one DNS transport attempt");
    unsigned pending = lwip_dns_pending();
    check(pending == test->pending, "late DNS callback owns retained slot");
    printf("DNS_RESULT %s status=%d stage=%d code=%d verify=%lu elapsed=%lld cancel_return=%lld pending=%u\n",
           test->label, status, diagnostic.stage, diagnostic.code, (unsigned long)diagnostic.verify_flags,
           (long long)elapsed, (long long)(cancelling ? end - cancel.fired : 0), pending);
    tls_stream_destroy(stream);
    idf_transport_destroy(&transport);
    check(transport.socket_fd == -1, "DNS context destroyed without socket");
}

static uint32_t remaining(void *argument)
{
    int64_t left = *(int64_t *)argument - now_ms();
    return left > 0 ? (uint32_t)left : 0;
}

static void pool_test(bool ready, void (*check)(bool, const char *))
{
    printf("ATTEMPT dns-pool\n");
    check(lwip_dns_pending() == 0, "DNS pool initially empty");
    for (unsigned i = 0; i < DNS_TABLE_SIZE; ++i) {
        char name[64];
        snprintf(name, sizeof(name), "pool-%u.lab.test", i);
        ip_addr_t address, sentinel;
        memset(&address, 0xa5, sizeof(address));
        memcpy(&sentinel, &address, sizeof(address));
        int64_t start = now_ms(), deadline = start + 60;
        int result = lwip_dns_resolve(name, &address, remaining, &deadline);
        int64_t elapsed = now_ms() - start;
        check(result == -1 && elapsed >= 60 && elapsed <= 310, "pool caller times out promptly");
        check(memcmp(&address, &sentinel, sizeof(address)) == 0, "timed-out DNS output unchanged");
        check(lwip_dns_pending() == i + 1, "pool retains only callback-owned slots");
        printf("DNS_POOL index=%u elapsed=%lld pending=%u\n", i, (long long)elapsed, lwip_dns_pending());
    }
    ip_addr_t address;
    int64_t start = now_ms(), deadline = start + 1000;
    int result = lwip_dns_resolve("overflow.lab.test", &address, remaining, &deadline);
    int64_t elapsed = now_ms() - start;
    check(result == -1 && elapsed >= 0 && elapsed <= 250, "full pool rejects promptly");
    check(lwip_dns_pending() == DNS_TABLE_SIZE, "lookup pool stays bounded");
    printf("DNS_FULL capacity=%u elapsed=%lld pending=%u\n", DNS_TABLE_SIZE, (long long)elapsed, lwip_dns_pending());
    authentication_recovery("literal-while-full", ready, check);
    check(lwip_dns_pending() == DNS_TABLE_SIZE, "literal did not require a DNS slot");
    check(drain_lookups(), "late replies retire saturated pool");
    printf("DNS_DRAIN pool pending=%u\n", lwip_dns_pending());
    authentication_hostname("recovery-pool", ready, check);
}

void dns_waits_probe(bool ready, void (*check)(bool, const char *))
{
    SemaphoreHandle_t configured = xSemaphoreCreateBinary();
    configASSERT(configured);
    configASSERT(tcpip_callback(configure_dns, configured) == ERR_OK);
    configASSERT(xSemaphoreTake(configured, pdMS_TO_TICKS(1000)) == pdTRUE);
    vSemaphoreDelete(configured);
    authentication_hostname("valid-hostname", ready, check);
    static const dns_case cases[] = {
        {"dns-negative", "absent.lab.test", 8443, 3000, 0, 1500,
         TLS_TRANSPORT_ERROR, TLS_STAGE_TCP_OPEN, 0, 0, 0},
        {"dns-timeout", "late.lab.test", 8443, 100, 100, 350,
         TLS_TIMEOUT, TLS_STAGE_TCP_OPEN, 0, 0, 1},
        {"dns-cancel", "cancel-late.lab.test", 8443, 3000, 0, 2999,
         TLS_CANCELLED, TLS_STAGE_TCP_OPEN, 0, 0, 1},
        {"dns-identity", "wrong.lab.test", 8443, 3000, 0, 1500,
         TLS_ERROR, TLS_STAGE_HANDSHAKE, MBEDTLS_ERR_X509_CERT_VERIFY_FAILED, MBEDTLS_X509_BADCERT_CN_MISMATCH, 0},
        {"dns-budget", "budget.lab.test", 8446, 1000, 1000, 1250,
         TLS_TIMEOUT, TLS_STAGE_HANDSHAKE, MBEDTLS_ERR_SSL_TIMEOUT, UINT32_MAX, 0}
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        failure_case(&cases[i], ready, check);
        /* The failing function's context and caller buffers no longer exist. */
        check(drain_lookups(), "late callback retired after caller destruction");
        printf("DNS_DRAIN %s pending=%u\n", cases[i].label, lwip_dns_pending());
        char label[64];
        snprintf(label, sizeof(label), "recovery-%s", cases[i].label);
        authentication_hostname(label, ready, check);
    }
    pool_test(ready, check);
}
