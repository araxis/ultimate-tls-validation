#ifndef TLS_LAB_THROUGHPUT_TESTS_H
#define TLS_LAB_THROUGHPUT_TESTS_H
struct throughput_results { unsigned checks; unsigned failures; };
struct throughput_results throughput_tests(const char *ca_path);
#endif
