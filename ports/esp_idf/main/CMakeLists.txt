idf_component_register(
    SRCS "probe.c" "authentication.c" "timing.c" "transport.c" "../../../src/tls_stream.c"
    INCLUDE_DIRS "." "../../../include" "${LAB_FIXTURE_DIR}"
    REQUIRES mbedtls esp_eth esp_netif esp_event esp_timer esp_hw_support lwip)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
