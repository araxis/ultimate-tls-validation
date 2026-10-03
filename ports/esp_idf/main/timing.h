#ifndef TLS_LAB_TIMING_H
#define TLS_LAB_TIMING_H
#include <stdbool.h>

void timing_probe(bool ready, void (*check)(bool, const char *));
#endif
