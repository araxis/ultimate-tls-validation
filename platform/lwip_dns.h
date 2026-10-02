#ifndef TLS_LAB_LWIP_DNS_H
#define TLS_LAB_LWIP_DNS_H
#include "lwip/ip_addr.h"
#include <stdint.h>

/* Called by a worker task. remaining_ms returns zero on cancellation or timeout.
 * The caller's context is never retained by lwIP's eventual DNS callback.
 * Failed lookups may retain a bounded internal slot until that callback arrives.
 */
int lwip_dns_resolve(const char *host, ip_addr_t *address,
                     uint32_t (*remaining_ms)(void *), void *context);
/* Outstanding internal slots, including abandoned lookups awaiting a callback. */
unsigned lwip_dns_pending(void);
#endif
