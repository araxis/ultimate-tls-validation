#ifndef TLS_LAB_CONNECT_TESTS_H
#define TLS_LAB_CONNECT_TESTS_H
struct connect_results { unsigned checks; unsigned failures; };
struct connect_results connect_tests(const char *ca_path);
#endif
