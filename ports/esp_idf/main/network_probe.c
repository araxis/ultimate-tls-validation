#include "network_probe.h"
#include "lwip_dns.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcp_priv.h"
#include "esp_timer.h"
#include <stdio.h>

typedef struct { SemaphoreHandle_t done; unsigned active, timewait, established; } network_state;

static void capture(void *argument)
{
    network_state *state = argument;
    for (struct tcp_pcb *p = tcp_active_pcbs; p; p = p->next) {
        ++state->active;
        if (p->state == ESTABLISHED) ++state->established;
    }
    for (struct tcp_pcb *p = tcp_tw_pcbs; p; p = p->next) ++state->timewait;
    xSemaphoreGive(state->done);
}

static network_state sample(SemaphoreHandle_t done)
{
    network_state state = {.done = done};
    configASSERT(tcpip_callback(capture, &state) == ERR_OK);
    configASSERT(xSemaphoreTake(done, pdMS_TO_TICKS(1000)) == pdTRUE);
    return state;
}

unsigned probe_established_connections(void)
{
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    configASSERT(done);
    network_state state = sample(done);
    vSemaphoreDelete(done);
    return state.established;
}

void probe_network_cooldown(const char *label, void (*check)(bool, const char *))
{
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    configASSERT(done);
    int64_t start = esp_timer_get_time();
    network_state state;
    do {
        state = sample(done);
        if (!state.active && !state.timewait) break;
        vTaskDelay(pdMS_TO_TICKS(2000));
    } while (esp_timer_get_time() - start < 135000000LL);
    unsigned pending = lwip_dns_pending();
    check(!state.active && !state.timewait && !pending, "network state drained naturally");
    printf("%s active=%u timewait=%u dns=%u elapsed=%lld\n", label,
           state.active, state.timewait, pending, (long long)((esp_timer_get_time() - start) / 1000));
    vSemaphoreDelete(done);
}
