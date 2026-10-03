#include "sessions.h"
#include "transport.h"
#include "authentication.h"
#include "network_probe.h"
#include "fixture.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    idf_transport transport;
    SemaphoreHandle_t ready, start, waiting, done;
    bool clock_ready, cancel, arm_read, initialized, marker, terminal, released;
    tls_status opened;
    tls_stream_diagnostics diagnostic;
    int count, core;
    size_t sent, received;
    int64_t ended;
    uint8_t response[128];
} session;

/* The fixture embeds the unchanged port context as its first member. */
static int observed_read(void *context, uint8_t *bytes, size_t length, uint32_t budget)
{
    session *s = context;
    if (s->arm_read) {
        s->arm_read = false;
        xSemaphoreGive(s->waiting);
    }
    tls_stream_port original = idf_transport_port(&s->transport);
    return original.read(&s->transport, bytes, length, budget);
}

static void run_session(void *argument)
{
    session *s = argument;
    s->core = xPortGetCoreID();
    s->initialized = idf_transport_init(&s->transport, lab_root, sizeof(lab_root)) == 0;
    s->transport.clock_ready = s->clock_ready;
    tls_stream_port port = idf_transport_port(&s->transport);
    port.read = observed_read;
    tls_stream *stream = tls_stream_create(&port);
    s->opened = s->initialized && stream ? tls_stream_open(stream, "192.0.2.1", s->cancel ? 8464 : 8465, 10000) : TLS_ERROR;
    xSemaphoreGive(s->ready);
    configASSERT(xSemaphoreTake(s->start, pdMS_TO_TICKS(5000)) == pdTRUE);
    static const uint8_t request[] = "GET /probe HTTP/1.1\r\nHost: tls.lab.test\r\nConnection: close\r\n\r\n";
    s->count = -1;
    if (s->opened == TLS_OK) {
        while (s->sent < sizeof(request)-1) {
            int n = tls_stream_write(stream, request+s->sent, sizeof(request)-1-s->sent);
            if (n <= 0) break;
            s->sent += (size_t)n;
        }
        if (s->cancel) {
            uint8_t marker = 0;
            s->marker = tls_stream_read(stream, &marker, 1) == 1 && marker == 1;
            s->arm_read = true;
            memset(s->response, 0xa5, sizeof(s->response));
            s->count = tls_stream_read(stream, s->response, sizeof(s->response));
        } else {
            while (s->received < sizeof(s->response) &&
                   (s->count = tls_stream_read(stream, s->response+s->received, sizeof(s->response)-s->received)) > 0)
                s->received += (size_t)s->count;
        }
    }
    s->ended = esp_timer_get_time();
    s->diagnostic = tls_stream_diagnostic(stream);
    if (s->cancel) {
        uint8_t sentinel = 0xa5;
        s->terminal = tls_stream_read(stream, &sentinel, 1) == -1 && sentinel == 0xa5 &&
                      tls_stream_write(stream, &sentinel, 1) == -1;
    }
    tls_stream_destroy(stream);
    idf_transport_destroy(&s->transport);
    s->released = s->transport.socket_fd == -1;
    xSemaphoreGive(s->done);
    vTaskDelete(NULL);
}

void sessions_probe(bool ready, void (*check)(bool, const char *))
{
    static const uint8_t response[] = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nlwip-ok\n";
    for (unsigned round = 0; round < 2; ++round) {
        session workers[2] = {{.clock_ready=ready,.cancel=true}, {.clock_ready=ready}};
        printf("ATTEMPT sessions-%u\n", round);
        for (unsigned i = 0; i < 2; ++i) {
            session *s = &workers[i];
            s->ready=xSemaphoreCreateBinary(); s->start=xSemaphoreCreateBinary();
            s->waiting=xSemaphoreCreateBinary(); s->done=xSemaphoreCreateBinary();
            configASSERT(s->ready && s->start && s->waiting && s->done);
            configASSERT(xTaskCreatePinnedToCore(run_session,"tls-session",12288,s,2,NULL,(i+round)%2)==pdPASS);
        }
        for (unsigned i=0;i<2;++i) configASSERT(xSemaphoreTake(workers[i].ready,pdMS_TO_TICKS(12000))==pdTRUE);
        unsigned live = probe_established_connections();
        check(workers[0].opened==TLS_OK && workers[1].opened==TLS_OK && live==2,
              "two authenticated sessions simultaneously established");
        check(workers[0].core==(int)round && workers[1].core==(int)(1-round), "sessions run on opposite selected cores");
        xSemaphoreGive(workers[0].start);
        configASSERT(xSemaphoreTake(workers[0].waiting,pdMS_TO_TICKS(5000))==pdTRUE);
        vTaskDelay(pdMS_TO_TICKS(5 * portTICK_PERIOD_MS));
        int64_t signal = esp_timer_get_time();
        atomic_store(&workers[0].transport.cancel_requested,true);
        configASSERT(xSemaphoreTake(workers[0].done,pdMS_TO_TICKS(5000))==pdTRUE);
        session *failed=&workers[0], *survivor=&workers[1];
        check(failed->marker && failed->sent==62 && failed->count==-1, "cancelled session reached blocked authenticated read");
        check(failed->diagnostic.status==TLS_CANCELLED && failed->diagnostic.stage==TLS_STAGE_READ &&
              failed->diagnostic.code==MBEDTLS_ERR_SSL_TIMEOUT && failed->diagnostic.verify_flags==0,
              "cancelled session has exact authenticated diagnostic");
        bool unchanged=true;
        for (size_t i=0;i<sizeof(failed->response);++i) unchanged &= failed->response[i]==0xa5;
        check(unchanged && failed->terminal && failed->released, "cancelled session preserves output and releases ownership");
        int64_t latency=(failed->ended-signal)/1000;
        check(latency>=0 && latency<=250, "cross-core cancellation completes within bound");
        unsigned remaining=probe_established_connections();
        check(remaining==1 && !atomic_load(&survivor->transport.cancel_requested), "survivor remains established and uncancelled");
        xSemaphoreGive(survivor->start);
        configASSERT(xSemaphoreTake(survivor->done,pdMS_TO_TICKS(12000))==pdTRUE);
        check(survivor->sent==62 && survivor->received==sizeof(response)-1 &&
              !memcmp(survivor->response,response,sizeof(response)-1), "survivor exchanges exact bytes after other session is destroyed");
        check(survivor->count==0 && survivor->diagnostic.status==TLS_OK && survivor->diagnostic.verify_flags==0 &&
              survivor->diagnostic.code==MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY && survivor->released,
              "survivor authenticates EOF and releases socket");
        printf("SESSION_RESULT round=%u cancelled_core=%d survivor_core=%d live=%u remaining=%u latency=%lld cancelled=%d survivor=%d sent=%zu received=%zu\n",
               round,failed->core,survivor->core,live,remaining,(long long)latency,failed->diagnostic.status,
               survivor->diagnostic.status,survivor->sent,survivor->received);
        for (unsigned i=0;i<2;++i) {
            vSemaphoreDelete(workers[i].ready); vSemaphoreDelete(workers[i].start);
            vSemaphoreDelete(workers[i].waiting); vSemaphoreDelete(workers[i].done);
        }
        char label[32];
        snprintf(label,sizeof(label),"session-recovery-%u",round);
        authentication_recovery(label,ready,check);
    }
    probe_network_cooldown("SESSION_CLEANUP",check);
}
