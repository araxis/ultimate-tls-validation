#ifndef TLS_LAB_IDF_RESOURCE_PROBE_H
#define TLS_LAB_IDF_RESOURCE_PROBE_H
#include <stdbool.h>
void resource_probe(bool ready, void (*check)(bool, const char *));
#endif
