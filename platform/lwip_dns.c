#include "lwip_dns.h"
#include "lwip/dns.h"
#include "lwip/tcpip.h"
#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
static portMUX_TYPE lookup_lock = portMUX_INITIALIZER_UNLOCKED;
#define LOCK_LOOKUPS() taskENTER_CRITICAL(&lookup_lock)
#define UNLOCK_LOOKUPS() taskEXIT_CRITICAL(&lookup_lock)
#else
#include "FreeRTOS.h"
#include "task.h"
#define LOCK_LOOKUPS() taskENTER_CRITICAL()
#define UNLOCK_LOOKUPS() taskEXIT_CRITICAL()
#endif
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
    LOCK_LOOKUPS();
    for (unsigned i = 0; i < DNS_TABLE_SIZE; ++i) {
        if (lookups[i].references) ++count;
    }
    UNLOCK_LOOKUPS();
    return count;
}

static void complete_lookup(const char *host, const ip_addr_t *address, void *context)
{
    struct lookup *lookup = context;
    (void)host;
    LOCK_LOOKUPS();
    configASSERT(lookup->references > 0 && !lookup->complete);
    lookup->resolved = address != NULL;
    if (address) lookup->address = *address;
    lookup->complete = true;
    --lookup->references;
    UNLOCK_LOOKUPS();
}

static void start_lookup(void *context)
{
    struct lookup *lookup = context;
    LOCK_LOOKUPS();
    bool abandoned = lookup->abandoned;
    UNLOCK_LOOKUPS();
    if (abandoned) {
        complete_lookup(NULL, NULL, lookup);
        return;
    }
    ip_addr_t address;
    err_t result = dns_gethostbyname_addrtype(lookup->host, &address, complete_lookup, lookup,
                                             LWIP_DNS_ADDRTYPE_IPV4);
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
    LOCK_LOOKUPS();
    for (unsigned i = 0; i < DNS_TABLE_SIZE; ++i) {
        if (!lookups[i].references) {
            lookup = &lookups[i];
            memset(lookup, 0, sizeof(*lookup));
            memcpy(lookup->host, host, length + 1);
            lookup->references = 2;
            break;
        }
    }
    UNLOCK_LOOKUPS();
    if (!lookup) return -1;

    /* Nonblocking submission: a full core queue cannot extend the deadline. */
    if (tcpip_try_callback(start_lookup, lookup) != ERR_OK) {
        LOCK_LOOKUPS();
        lookup->references = 0;
        UNLOCK_LOOKUPS();
        return -1;
    }
    int result = -1;
    for (;;) {
        uint32_t left = remaining_ms(context);
        LOCK_LOOKUPS();
        if (lookup->complete || !left) {
            if (left && lookup->complete && lookup->resolved) {
                *address = lookup->address;
                result = 0;
            }
            lookup->abandoned = !lookup->complete;
            configASSERT(lookup->references > 0);
            --lookup->references;
            UNLOCK_LOOKUPS();
            return result;
        }
        UNLOCK_LOOKUPS();
        TickType_t ticks = pdMS_TO_TICKS(left < 10 ? left : 10);
        vTaskDelay(ticks ? ticks : 1);
    }
}
