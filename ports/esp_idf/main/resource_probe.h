#ifndef TLS_LAB_IDF_RESOURCE_PROBE_H
#define TLS_LAB_IDF_RESOURCE_PROBE_H
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
void resource_snapshot(unsigned attempt, const char *phase, SemaphoreHandle_t done,
                       void (*check)(bool, const char *));
void resource_cooldown(unsigned attempt, SemaphoreHandle_t done, void (*check)(bool, const char *));
void resource_probe(bool ready, void (*check)(bool, const char *));
#endif
