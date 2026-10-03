#ifndef TLS_LAB_IDF_ALLOCATION_METER_H
#define TLS_LAB_IDF_ALLOCATION_METER_H
#include <stdbool.h>
#include <stddef.h>
typedef struct {
    size_t bytes, peak, core_bytes, crypto_bytes;
    unsigned live, allocations;
    unsigned rejected;
    size_t rejected_bytes;
} allocation_totals;
void allocation_meter_begin(void);
void allocation_meter_pause(bool paused);
allocation_totals allocation_meter_read(void);
void allocation_meter_end(void);
/* Fail one scoped allocation after this many allowed calls; test task only. */
void allocation_meter_fail_after(size_t allowed_calls);
#endif
