#ifndef TLS_LAB_IDF_NETWORK_PROBE_H
#define TLS_LAB_IDF_NETWORK_PROBE_H
#include <stdbool.h>
unsigned probe_established_connections(void);
void probe_network_cooldown(const char *label, void (*check)(bool, const char *));
#endif
