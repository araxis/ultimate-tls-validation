#ifndef TLS_LAB_ALLOCATION_TESTS_H
#define TLS_LAB_ALLOCATION_TESTS_H
struct allocation_results { unsigned checks; unsigned failures; };
struct allocation_results allocation_tests(const char *ca_path);
#endif
