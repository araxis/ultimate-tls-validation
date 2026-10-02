#ifndef TLS_LAB_BOUNDARY_TESTS_H
#define TLS_LAB_BOUNDARY_TESTS_H
struct boundary_results { unsigned checks; unsigned failures; };
struct boundary_results boundary_tests(const char *ca_path);
#endif
