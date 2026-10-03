idf_component_register(
    SRCS "probe.c" "authentication.c" "timing.c" "socket_waits.c" "dns_waits.c" "transport.c" "../../../src/tls_stream.c" "../../../platform/lwip_dns.c"
    INCLUDE_DIRS "." "../../../include" "../../../platform" "${LAB_FIXTURE_DIR}"
    REQUIRES mbedtls esp_eth esp_netif esp_event esp_timer esp_hw_support lwip)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
