#ifndef TLS_LAB_PRESSURE_TESTS_H
#define TLS_LAB_PRESSURE_TESTS_H
struct pressure_results {
    unsigned checks;
    unsigned failures;
};
struct pressure_results pressure_tests(const char *ca_path);
#endif
