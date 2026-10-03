#ifndef TLS_LAB_IDF_ALLOCATION_FAILURES_H
#define TLS_LAB_IDF_ALLOCATION_FAILURES_H
#include <stdbool.h>
void allocation_failures_probe(bool ready, void (*check)(bool, const char *));
#endif
