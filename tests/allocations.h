#ifndef TLS_LAB_ALLOCATION_TESTS_H
#define TLS_LAB_ALLOCATION_TESTS_H
#include <stddef.h>
struct allocation_measurement { unsigned live; size_t bytes, peak; };
void allocation_measure_begin(void);
struct allocation_measurement allocation_measure_read(void);
struct allocation_measurement allocation_measure_end(void);
struct allocation_results { unsigned checks; unsigned failures; };
struct allocation_results allocation_tests(const char *ca_path);
struct allocation_results handshake_allocation_tests(const char *ca_path);
#endif
