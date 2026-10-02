#ifndef TLS_LAB_SECURITY_TESTS_H
#define TLS_LAB_SECURITY_TESTS_H
struct security_results { unsigned checks; unsigned failures; };
struct security_results security_tests(const char *ca_path);
#endif
