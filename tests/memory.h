#ifndef TLS_LAB_MEMORY_TESTS_H
#define TLS_LAB_MEMORY_TESTS_H
struct memory_results { unsigned checks; unsigned failures; };
struct memory_results memory_tests(const char *ca_path);
#endif
