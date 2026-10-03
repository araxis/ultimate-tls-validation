idf_component_register(
    SRCS "probe.c" "authentication.c" "timing.c" "socket_waits.c" "dns_waits.c" "resource_probe.c" "allocation_meter.c" "transport.c" "../../../src/tls_stream.c" "../../../platform/lwip_dns.c"
    INCLUDE_DIRS "." "../../../include" "../../../platform" "${LAB_FIXTURE_DIR}"
    REQUIRES mbedtls esp_eth esp_netif esp_event esp_timer esp_hw_support lwip heap)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
if(LAB_MEMORY_ACCOUNTING)
    set_property(SOURCE "${CMAKE_CURRENT_LIST_DIR}/../../../src/tls_stream.c" APPEND PROPERTY
        COMPILE_DEFINITIONS "calloc=lab_stream_calloc" "free=lab_stream_free")
    target_link_options(${COMPONENT_LIB} INTERFACE
        "LINKER:--wrap=esp_mbedtls_mem_calloc" "LINKER:--wrap=esp_mbedtls_mem_free")
endif()
