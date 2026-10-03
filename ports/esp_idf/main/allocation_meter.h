#ifndef TLS_LAB_IDF_ALLOCATION_METER_H
#define TLS_LAB_IDF_ALLOCATION_METER_H
#include <stdbool.h>
#include <stddef.h>
typedef struct {
    size_t bytes, peak, core_bytes, crypto_bytes;
    unsigned live, allocations;
} allocation_totals;
void allocation_meter_begin(void);
void allocation_meter_pause(bool paused);
allocation_totals allocation_meter_read(void);
void allocation_meter_end(void);
#endif
