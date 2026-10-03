#ifndef TLS_LAB_DNS_WAITS_H
#define TLS_LAB_DNS_WAITS_H
#include <stdbool.h>
void dns_waits_probe(bool ready, void (*check)(bool, const char *));
#endif
