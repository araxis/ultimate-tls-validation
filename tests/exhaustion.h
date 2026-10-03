#ifndef TLS_LAB_EXHAUSTION_TESTS_H
#define TLS_LAB_EXHAUSTION_TESTS_H
struct exhaustion_results { unsigned checks, failures; };
struct exhaustion_results exhaustion_tests(const char *ca_path);
#endif
