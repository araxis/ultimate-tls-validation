#ifndef TLS_LAB_SESSION_TESTS_H
#define TLS_LAB_SESSION_TESTS_H
struct session_results { unsigned checks; unsigned failures; };
struct session_results session_tests(const char *ca_path);
#endif
