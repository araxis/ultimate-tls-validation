#ifndef TLS_LAB_ALLOCATION_TESTS_H
#define TLS_LAB_ALLOCATION_TESTS_H
#include <stddef.h>
struct allocation_measurement { unsigned live; size_t bytes, peak; unsigned rejected; size_t phase_peak; };
void allocation_measure_begin(void);
/* Start a phase at current live bytes without clearing the lifetime peak. */
void allocation_measure_phase(void);
/* Bound simultaneous requested bytes on the owning test thread. SIZE_MAX lifts
 * the limit; this does not reserve or exhaust the host's process-wide heap. */
void allocation_measure_limit(size_t bytes);
struct allocation_measurement allocation_measure_read(void);
struct allocation_measurement allocation_measure_end(void);
struct allocation_results { unsigned checks; unsigned failures; };
struct allocation_results allocation_tests(const char *ca_path);
struct allocation_results handshake_allocation_tests(const char *ca_path);
#endif
