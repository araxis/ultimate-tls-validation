#ifndef TLS_LAB_CHAIN_TESTS_H
#define TLS_LAB_CHAIN_TESTS_H
struct chain_results { unsigned checks, failures; };
struct chain_results chain_tests(const char *ca_path);
#endif
