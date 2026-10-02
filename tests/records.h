#ifndef TLS_LAB_RECORD_TESTS_H
#define TLS_LAB_RECORD_TESTS_H
struct record_results { unsigned checks; unsigned failures; };
struct record_results record_tests(const char *ca_path);
#endif
