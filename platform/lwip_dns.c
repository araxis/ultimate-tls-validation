#include "lwip_dns.h"
#include "lwip/dns.h"
#include "lwip/tcpip.h"
#include "FreeRTOS.h"
#include "task.h"
#include <stdbool.h>
#include <string.h>

/* A slot has two owners: the waiting task and the queued/core DNS callback.
 * Neither the hostname nor the result refers to the caller's stack. A cancelled
 * wait drops only the task's reference; late callbacks retire their own reference
 * before reuse. A fixed pool bounds retention during repeated cancellations.
 */
struct lookup {
    char host[254];
    ip_addr_t address;
    unsigned references;
    bool complete, resolved, abandoned;
};
static struct lookup lookups[DNS_TABLE_SIZE];

unsigned lwip_dns_pending(void)
{
    unsigned count = 0;
    taskENTER_CRITICAL();
    for (unsigned i = 0; i < DNS_TABLE_SIZE; ++i) {
        if (lookups[i].references) ++count;
    }
    taskEXIT_CRITICAL();
    return count;
}

static void complete_lookup(const char *host, const ip_addr_t *address, void *context)
{
    struct lookup *lookup = context;
    (void)host;
    taskENTER_CRITICAL();
    configASSERT(lookup->references > 0 && !lookup->complete);
    lookup->resolved = address != NULL;
    if (address) lookup->address = *address;
    lookup->complete = true;
    --lookup->references;
    taskEXIT_CRITICAL();
}

static void start_lookup(void *context)
{
    struct lookup *lookup = context;
    taskENTER_CRITICAL();
    bool abandoned = lookup->abandoned;
    taskEXIT_CRITICAL();
    if (abandoned) {
        complete_lookup(NULL, NULL, lookup);
        return;
    }
    ip_addr_t address;
    err_t result = dns_gethostbyname(lookup->host, &address, complete_lookup, lookup);
    if (result != ERR_INPROGRESS) {
        complete_lookup(NULL, result == ERR_OK ? &address : NULL, lookup);
    }
}

int lwip_dns_resolve(const char *host, ip_addr_t *address,
                     uint32_t (*remaining_ms)(void *), void *context)
{
    if (!host || !address || !remaining_ms || !remaining_ms(context)) return -1;
    size_t length = strnlen(host, sizeof(lookups[0].host));
    if (!length || length >= sizeof(lookups[0].host)) return -1;
    struct lookup *lookup = NULL;
    taskENTER_CRITICAL();
    for (unsigned i = 0; i < DNS_TABLE_SIZE; ++i) {
        if (!lookups[i].references) {
            lookup = &lookups[i];
            memset(lookup, 0, sizeof(*lookup));
            memcpy(lookup->host, host, length + 1);
            lookup->references = 2;
            break;
        }
    }
    taskEXIT_CRITICAL();
    if (!lookup) return -1;

    /* Nonblocking submission: a full core queue cannot extend the deadline. */
    if (tcpip_try_callback(start_lookup, lookup) != ERR_OK) {
        taskENTER_CRITICAL();
        lookup->references = 0;
        taskEXIT_CRITICAL();
        return -1;
    }
    int result = -1;
    for (;;) {
        uint32_t left = remaining_ms(context);
        taskENTER_CRITICAL();
        if (lookup->complete || !left) {
            if (left && lookup->complete && lookup->resolved) {
                *address = lookup->address;
                result = 0;
            }
            lookup->abandoned = !lookup->complete;
            configASSERT(lookup->references > 0);
            --lookup->references;
            taskEXIT_CRITICAL();
            return result;
        }
        taskEXIT_CRITICAL();
        vTaskDelay(pdMS_TO_TICKS(left < 10 ? left : 10));
    }
}
