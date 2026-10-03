#include "timing.h"
#include "authentication.h"
#include "transport.h"
#include "fixture.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    /* First member: unchanged adapter callbacks receive this same address. */
    idf_transport transport;
    int (*receive)(void *, uint8_t *, size_t, uint32_t);
    TaskHandle_t worker;
    SemaphoreHandle_t done;
    bool armed, notified;
    int64_t armed_ms, fired_ms;
} timing_context;

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

static void cancel_worker(void *argument)
{
    timing_context *context = argument;
    uint32_t command = 0;
    xTaskNotifyWait(0, UINT32_MAX, &command, portMAX_DELAY);
    if (command == 1) {
        vTaskDelay(pdMS_TO_TICKS(50));
        context->fired_ms = now_ms();
        atomic_store(&context->transport.cancel_requested, true);
    }
    /* No context access after signaling completion. */
    xSemaphoreGive(context->done);
    vTaskDelete(NULL);
}

static int receive_bytes(void *argument, uint8_t *bytes, size_t length, uint32_t budget)
{
    timing_context *context = argument;
    if (context->armed && !context->notified && context->worker) {
        context->notified = true;
        context->armed_ms = now_ms();
        xTaskNotify(context->worker, 1, eSetValueWithOverwrite);
    }
    return context->receive(&context->transport, bytes, length, budget);
}

static void run_fault(const char *label, bool reading, bool cancel, bool ready,
                      void (*check)(bool, const char *))
{
    printf("ATTEMPT %s\n", label);
    timing_context context = {0};
    check(idf_transport_init(&context.transport, lab_root, sizeof(lab_root)) == 0, "fixture trust anchor loaded");
    context.transport.clock_ready = ready;
    tls_stream_port port = idf_transport_port(&context.transport);
    context.receive = port.read;
    port.read = receive_bytes;
    tls_stream *stream = tls_stream_create(&port);
    check(stream != NULL, "stream allocated");
    if (cancel) {
        context.done = xSemaphoreCreateBinary();
        if (context.done && xTaskCreate(cancel_worker, "cancel-test", 2048, &context, 2,
                                       &context.worker) != pdPASS) context.worker = NULL;
    }
    check(!cancel || context.worker != NULL, "cancellation worker ready");
    context.armed = cancel && !reading;
    uint32_t budget = cancel ? 10000 : (reading ? 3000 : 1500);
    int64_t start = now_ms();
    tls_status status = tls_stream_open(stream, "192.0.2.1", reading ? 8447 : 8446, budget);
    uint8_t output[8], sentinel[8];
    memset(output, 0xa5, sizeof(output));
    memcpy(sentinel, output, sizeof(output));
    int count = -1;
    int64_t read_start = 0;
    if (reading) {
        check(status == TLS_OK && tls_stream_diagnostic(stream).verify_flags == 0, "read starts after verified handshake");
        static const uint8_t request[] = "GET /probe HTTP/1.1\r\nHost: tls.lab.test\r\nConnection: close\r\n\r\n";
        size_t sent = 0;
        while (status == TLS_OK && sent < sizeof(request) - 1) {
            count = tls_stream_write(stream, request + sent, sizeof(request) - 1 - sent);
            if (count <= 0) break;
            sent += (size_t)count;
        }
        check(sent == sizeof(request) - 1, "stalled read request complete");
        if (!cancel) vTaskDelay(pdMS_TO_TICKS(500));
        context.armed = cancel;
        read_start = now_ms() - start;
        count = tls_stream_read(stream, output, sizeof(output));
        status = tls_stream_status(stream);
    }
    int64_t end = now_ms();
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    if (context.worker && !context.notified) xTaskNotify(context.worker, 2, eSetValueWithOverwrite);
    bool joined = !context.worker || xSemaphoreTake(context.done, pdMS_TO_TICKS(1000)) == pdTRUE;
    check(joined, "cancellation worker finished before context release");
    configASSERT(joined);
    if (context.done) vSemaphoreDelete(context.done);
    check(status == (cancel ? TLS_CANCELLED : TLS_TIMEOUT) && diagnostic.status == status &&
          diagnostic.stage == (reading ? TLS_STAGE_READ : TLS_STAGE_HANDSHAKE) &&
          diagnostic.verify_flags == (reading ? 0 : UINT32_MAX) &&
          diagnostic.code == MBEDTLS_ERR_SSL_TIMEOUT && (!reading || count == -1), "exact terminal diagnostic");
    int64_t elapsed = end - start;
    check(cancel ? (context.fired_ms > 0 && end >= context.fired_ms && end - context.fired_ms <= 250 && elapsed < budget) :
                   (elapsed >= budget && elapsed <= budget + 250 && (!reading || read_start >= 500)), "bounded total wait");
    check(cancel ? (context.notified && context.fired_ms - context.armed_ms >= 40 &&
                    atomic_load(&context.transport.cancel_requested)) :
                   !atomic_load(&context.transport.cancel_requested), "expected cancellation signal");
    check(context.transport.socket_fd == -1, "failure released socket");
    check(tls_stream_read(stream, output, sizeof(output)) == -1, "terminal read refused");
    check(tls_stream_write(stream, sentinel, sizeof(sentinel)) == -1, "terminal write refused");
    check(memcmp(output, sentinel, sizeof(output)) == 0, "failed read preserved output");
    tls_stream_diagnostics after = tls_stream_diagnostic(stream);
    check(after.status == diagnostic.status && after.stage == diagnostic.stage &&
          after.code == diagnostic.code && after.verify_flags == diagnostic.verify_flags, "terminal diagnostic stable");
    printf("TIMING %s status=%d stage=%d code=%d verify=%lu elapsed=%lld read_start=%lld cancel_delay=%lld cancel_return=%lld opens=%u\n",
           label, diagnostic.status, diagnostic.stage, diagnostic.code, (unsigned long)diagnostic.verify_flags,
           (long long)elapsed, (long long)read_start,
           (long long)(cancel ? context.fired_ms - context.armed_ms : 0),
           (long long)(cancel ? end - context.fired_ms : 0), context.transport.open_calls);
    tls_stream_destroy(stream);
    check(context.transport.socket_fd == -1, "socket released after destroy");
    idf_transport_destroy(&context.transport);
}

void timing_probe(bool ready, void (*check)(bool, const char *))
{
    static const char *labels[] = {"handshake-timeout", "handshake-cancel", "read-timeout", "read-cancel"};
    for (unsigned i = 0; i < 4; ++i) {
        run_fault(labels[i], i >= 2, i % 2 != 0, ready, check);
        char recovery[64];
        snprintf(recovery, sizeof(recovery), "recovery-%s", labels[i]);
        authentication_recovery(recovery, ready, check);
    }
}
