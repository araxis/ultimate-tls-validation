#include "allocation_meter.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if !CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC
#error "Accounting wrappers require the verified internal-heap Mbed TLS allocator path"
#endif

/* Source and link wrappers forward to unchanged allocators. Only the designated task
 * is tracked. Metadata is static and excluded from requested-byte accounting. */
static _Atomic(TaskHandle_t) owner;
static bool paused;
static allocation_totals totals;
static size_t fail_after = SIZE_MAX;
static unsigned armed_allocations;
static struct { void *pointer; size_t bytes; bool crypto; uintptr_t caller; } slots[256];

void *__real_esp_mbedtls_mem_calloc(size_t count, size_t size);
void __real_esp_mbedtls_mem_free(void *pointer);

static bool owned(void)
{
    TaskHandle_t task = atomic_load(&owner);
    return task && task == xTaskGetCurrentTaskHandle();
}

static void record(void *pointer, size_t count, size_t size, bool crypto, uintptr_t caller)
{
    if (!pointer || !owned() || paused) return;
    configASSERT(!size || count <= SIZE_MAX / size);
    for (unsigned i = 0; i < 256; ++i) {
        if (!slots[i].pointer) {
            slots[i].pointer = pointer;
            slots[i].bytes = count * size;
            slots[i].crypto = crypto;
            slots[i].caller = caller;
            totals.bytes += count * size;
            if (crypto) totals.crypto_bytes += count * size;
            else totals.core_bytes += count * size;
            ++totals.live;
            ++totals.allocations;
            if (totals.bytes > totals.peak) totals.peak = totals.bytes;
            return;
        }
    }
    configASSERT(false); /* Tracker exhaustion must fail, never undercount. */
}

static bool deny(size_t count, size_t size)
{
    if (!owned() || paused || fail_after == SIZE_MAX) return false;
    if (fail_after) { --fail_after; return false; }
    configASSERT(!size || count <= SIZE_MAX / size);
    fail_after = SIZE_MAX;
    ++totals.rejected;
    totals.rejected_bytes = count * size;
    totals.rejected_prior = totals.allocations - armed_allocations;
    totals.rejected_live_bytes = totals.bytes;
    return true;
}

void allocation_meter_fail_after(size_t allowed_calls)
{
    configASSERT(owned() && !paused && fail_after == SIZE_MAX);
    fail_after = allowed_calls;
    armed_allocations = totals.allocations;
    totals.injection_base_bytes = totals.bytes;
}

static void release(void *pointer)
{
    if (!pointer || !owned()) return;
    for (unsigned i = 0; i < 256; ++i) {
        if (slots[i].pointer == pointer) {
            totals.bytes -= slots[i].bytes;
            if (slots[i].crypto) totals.crypto_bytes -= slots[i].bytes;
            else totals.core_bytes -= slots[i].bytes;
            --totals.live;
            slots[i].pointer = NULL;
            return;
        }
    }
}

void *lab_stream_calloc(size_t count, size_t size)
{
    if (deny(count, size)) return NULL;
    void *pointer = calloc(count, size);
    record(pointer, count, size, false, (uintptr_t)__builtin_return_address(0));
    return pointer;
}

void lab_stream_free(void *pointer)
{
    release(pointer);
    free(pointer);
}

void *__wrap_esp_mbedtls_mem_calloc(size_t count, size_t size)
{
    if (deny(count, size)) return NULL;
    void *pointer = __real_esp_mbedtls_mem_calloc(count, size);
    record(pointer, count, size, true, (uintptr_t)__builtin_return_address(0));
    return pointer;
}

void __wrap_esp_mbedtls_mem_free(void *pointer)
{
    release(pointer);
    __real_esp_mbedtls_mem_free(pointer);
}

void allocation_meter_begin(void)
{
    configASSERT(!atomic_load(&owner) && !totals.live);
    memset(slots, 0, sizeof(slots));
    memset(&totals, 0, sizeof(totals));
    paused = false;
    fail_after = SIZE_MAX;
    atomic_store(&owner, xTaskGetCurrentTaskHandle());
}

void allocation_meter_pause(bool value) { configASSERT(owned()); paused = value; }
allocation_totals allocation_meter_read(void) { configASSERT(owned()); return totals; }
void allocation_meter_end(void)
{
    paused = true;
    for (unsigned i = 0; i < 256; ++i) {
        if (slots[i].pointer)
            printf("RETAINED bytes=%zu crypto=%u caller=0x%08lx\n", slots[i].bytes,
                   slots[i].crypto, (unsigned long)slots[i].caller);
    }
    configASSERT(owned() && !totals.live && !totals.bytes);
    atomic_store(&owner, NULL);
}
