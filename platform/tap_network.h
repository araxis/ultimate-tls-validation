#ifndef TLS_LAB_TAP_NETWORK_H
#define TLS_LAB_TAP_NETWORK_H
#include <stdint.h>
/* One interface per process. Open before starting the scheduler. */
int tap_network_open(const char *name);
void tap_network_start(void);
void tap_network_close(void);
void tap_network_counts(uint32_t *received, uint32_t *sent);
#endif
