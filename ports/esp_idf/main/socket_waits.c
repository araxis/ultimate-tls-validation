#include "socket_waits.h"
#include "authentication.h"
#include "transport.h"
#include "fixture.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/sockets.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    /* First member preserves the address expected by adapter callbacks. */
    idf_transport transport;
    int (*send)(void *, const uint8_t *, size_t, uint32_t);
    SemaphoreHandle_t trigger, done;
    TaskHandle_t worker;
    atomic_bool stopping;
    bool armed;
    unsigned blocked;
    int64_t fired_ms;
} wait_context;

/* Accessed only by the lwIP core while installed. Restoration is a barrier. */
static struct {
    struct netif *interface;
    netif_linkoutput_fn original;
    SemaphoreHandle_t trigger;
    uint16_t port;
    bool discard;
    unsigned syns, drops;
} link_fault;

static int64_t now_ms(void) { return esp_timer_get_time() / 1000; }

static err_t fault_output(struct netif *interface, struct pbuf *packet)
{
    uint8_t header[128];
    unsigned copied = pbuf_copy_partial(packet, header, sizeof(header), 0);
    if (copied >= 54 && header[12] == 8 && header[13] == 0 &&
        (header[14] >> 4) == 4 && header[23] == 6 &&
        header[30] == 192 && header[31] == 0 && header[32] == 2 && header[33] == 1) {
        unsigned tcp = 14 + (header[14] & 15U) * 4;
        if (tcp >= 34 && copied >= tcp + 20 &&
            ((unsigned)header[tcp + 2] * 256 + header[tcp + 3]) == link_fault.port &&
            (header[tcp + 13] & 0x12) == 0x02) {
            ++link_fault.syns;
            xSemaphoreGive(link_fault.trigger);
            if (link_fault.discard) { ++link_fault.drops; return ERR_OK; }
        }
    }
    return link_fault.original(interface, packet);
}

typedef struct { SemaphoreHandle_t done; bool install; } link_change;

static void configure_link(void *argument)
{
    link_change *change = argument;
    if (change->install) {
        configASSERT(netif_default && !link_fault.original);
        link_fault.interface = netif_default;
        link_fault.original = netif_default->linkoutput;
        netif_default->linkoutput = fault_output;
    } else {
        configASSERT(link_fault.interface->linkoutput == fault_output);
        link_fault.interface->linkoutput = link_fault.original;
        link_fault.original = NULL;
    }
    xSemaphoreGive(change->done);
}

static void change_link(bool install)
{
    link_change change = {xSemaphoreCreateBinary(), install};
    configASSERT(change.done);
    configASSERT(tcpip_callback(configure_link, &change) == ERR_OK);
    configASSERT(xSemaphoreTake(change.done, pdMS_TO_TICKS(1000)) == pdTRUE);
    vSemaphoreDelete(change.done);
}

static void cancel_worker(void *argument)
{
    wait_context *context = argument;
    xSemaphoreTake(context->trigger, portMAX_DELAY);
    if (!atomic_load(&context->stopping)) {
        context->armed = true;
        vTaskDelay(pdMS_TO_TICKS(50));
        context->fired_ms = now_ms();
        atomic_store(&context->transport.cancel_requested, true);
    }
    xSemaphoreGive(context->done);
    vTaskDelete(NULL);
}

static int send_bytes(void *argument, const uint8_t *bytes, size_t length, uint32_t budget)
{
    wait_context *context = argument;
    fd_set writable;
    FD_ZERO(&writable);
    FD_SET(context->transport.socket_fd, &writable);
    struct timeval immediate = {0};
    if (lwip_select(context->transport.socket_fd + 1, NULL, &writable, NULL, &immediate) == 0) {
        ++context->blocked;
        xSemaphoreGive(context->trigger);
    }
    return context->send(&context->transport, bytes, length, budget);
}

static void run_case(const char *label, bool writing, bool cancel, bool refused, bool ready,
                     void (*check)(bool, const char *))
{
    printf("ATTEMPT %s\n", label);
    wait_context context = {0};
    check(idf_transport_init(&context.transport, lab_root, sizeof(lab_root)) == 0, "fixture trust anchor loaded");
    context.transport.clock_ready = ready;
    atomic_init(&context.stopping, false);
    context.trigger = xSemaphoreCreateBinary();
    context.done = xSemaphoreCreateBinary();
    configASSERT(context.trigger && context.done);
    tls_stream_port port = idf_transport_port(&context.transport);
    context.send = port.write;
    if (writing) port.write = send_bytes;
    tls_stream *stream = tls_stream_create(&port);
    check(stream != NULL, "stream allocated");
    if (cancel && xTaskCreate(cancel_worker, "socket-cancel", 2048, &context, 2, &context.worker) != pdPASS)
        context.worker = NULL;
    check(!cancel || context.worker != NULL, "cancellation worker ready");
    if (!writing) {
        link_fault.port = refused ? 8448 : 8449;
        link_fault.discard = !refused;
        link_fault.syns = link_fault.drops = 0;
        link_fault.trigger = context.trigger;
        change_link(true);
    }
    uint32_t budget = cancel ? 10000 : (writing ? 4000 : 1500);
    int64_t start = now_ms();
    tls_status status = tls_stream_open(stream, "192.0.2.1", writing ? 8450 : link_fault.port, budget);
    size_t sent = 0;
    int count = -1;
    if (writing) {
        check(status == TLS_OK && tls_stream_diagnostic(stream).verify_flags == 0, "write starts after verified handshake");
        uint8_t token = 0;
        check(tls_stream_read(stream, &token, 1) == 1 && token == 1, "peer ready to stop consuming writes");
        uint8_t payload[512];
        memset(payload, 0x5a, sizeof(payload));
        while (status == TLS_OK && sent < 262144) {
            count = tls_stream_write(stream, payload, sizeof(payload));
            if (count <= 0) break;
            sent += (size_t)count;
        }
        status = tls_stream_status(stream);
    }
    int64_t end = now_ms();
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    if (!writing) change_link(false);
    atomic_store(&context.stopping, true);
    xSemaphoreGive(context.trigger);
    bool joined = !context.worker || xSemaphoreTake(context.done, pdMS_TO_TICKS(1000)) == pdTRUE;
    check(joined, "cancellation worker finished before context release");
    configASSERT(joined);
    check(status == (refused ? TLS_TRANSPORT_ERROR : cancel ? TLS_CANCELLED : TLS_TIMEOUT) &&
          diagnostic.status == status && diagnostic.stage == (writing ? TLS_STAGE_WRITE : TLS_STAGE_TCP_OPEN) &&
          diagnostic.code == (writing ? MBEDTLS_ERR_SSL_TIMEOUT : 0) && diagnostic.verify_flags == 0 &&
          (!writing || count == -1), "exact terminal diagnostic");
    int64_t elapsed = end - start;
    check(refused ? (elapsed >= 0 && elapsed <= 500) : cancel ?
          (context.fired_ms > 0 && end >= context.fired_ms && end - context.fired_ms <= 250 && elapsed < budget) :
          (elapsed >= budget && elapsed <= budget + 250), "bounded socket wait");
    check(cancel ? context.armed && atomic_load(&context.transport.cancel_requested) :
                   !atomic_load(&context.transport.cancel_requested), "expected cancellation signal");
    check(context.transport.socket_fd == -1, "failure released socket");
    uint8_t output[8], sentinel[8];
    memset(output, 0xa5, sizeof(output));
    memcpy(sentinel, output, sizeof(output));
    check(tls_stream_read(stream, output, sizeof(output)) == -1, "terminal read refused");
    check(tls_stream_write(stream, sentinel, sizeof(sentinel)) == -1, "terminal write refused");
    check(memcmp(output, sentinel, sizeof(output)) == 0, "terminal read preserved output");
    tls_stream_diagnostics after = tls_stream_diagnostic(stream);
    check(after.status == diagnostic.status && after.stage == diagnostic.stage &&
          after.code == diagnostic.code && after.verify_flags == diagnostic.verify_flags, "terminal diagnostic stable");
    check(writing ? context.blocked > 0 && sent > 0 && sent < 262144 :
          link_fault.syns > 0 && (refused ? link_fault.drops == 0 : link_fault.drops == link_fault.syns),
          "actual socket wait mechanism observed");
    check(context.transport.open_calls == 1, "single transport open attempt");
    printf("SOCKET_WAIT %s status=%d stage=%d code=%d verify=%lu elapsed=%lld cancel_return=%lld syns=%u drops=%u blocked=%u sent=%zu opens=%u\n",
           label, diagnostic.status, diagnostic.stage, diagnostic.code, (unsigned long)diagnostic.verify_flags,
           (long long)elapsed, (long long)(cancel ? end - context.fired_ms : 0),
           writing ? 0 : link_fault.syns, writing ? 0 : link_fault.drops, context.blocked, sent, context.transport.open_calls);
    tls_stream_destroy(stream);
    check(context.transport.socket_fd == -1, "socket released after destroy");
    idf_transport_destroy(&context.transport);
    vSemaphoreDelete(context.trigger);
    vSemaphoreDelete(context.done);
}

void socket_waits_probe(bool ready, void (*check)(bool, const char *))
{
    static const char *labels[] = {"connect-refused", "connect-timeout", "connect-cancel", "write-timeout", "write-cancel"};
    for (unsigned i = 0; i < 5; ++i) {
        run_case(labels[i], i >= 3, i == 2 || i == 4, i == 0, ready, check);
        char recovery[64];
        snprintf(recovery, sizeof(recovery), "recovery-%s", labels[i]);
        authentication_recovery(recovery, ready, check);
    }
}
