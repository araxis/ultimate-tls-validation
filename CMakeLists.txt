cmake_minimum_required(VERSION 3.20)
project(ultimate_tls_lab C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
option(TLS_LAB_UBSAN "Instrument the probe and dependencies for undefined behavior" OFF)
if(TLS_LAB_UBSAN)
    add_compile_options(-fsanitize=undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined -fno-sanitize-recover=all)
endif()

set(FREERTOS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/.deps/freertos)
set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/.deps/lwip)
set(POSIX_PORT ${FREERTOS_DIR}/portable/ThirdParty/GCC/Posix)
add_library(kernel STATIC
    ${FREERTOS_DIR}/tasks.c ${FREERTOS_DIR}/queue.c ${FREERTOS_DIR}/list.c
    ${FREERTOS_DIR}/portable/MemMang/heap_4.c
    ${POSIX_PORT}/port.c ${POSIX_PORT}/utils/wait_for_event.c)
target_include_directories(kernel PUBLIC config ${FREERTOS_DIR}/include ${POSIX_PORT})
target_link_libraries(kernel PUBLIC pthread)

include(${LWIP_DIR}/src/Filelists.cmake)
add_library(lwip STATIC ${lwipcore_SRCS} ${lwipcore4_SRCS} ${lwipapi_SRCS}
    ${LWIP_DIR}/src/netif/ethernet.c ${LWIP_DIR}/contrib/ports/freertos/sys_arch.c)
target_include_directories(lwip PUBLIC config ${LWIP_DIR}/src/include
    ${LWIP_DIR}/contrib/ports/freertos/include)
target_link_libraries(lwip PUBLIC kernel)

set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
add_subdirectory(.deps/mbedtls EXCLUDE_FROM_ALL)
add_library(tls_stream STATIC src/tls_stream.c)
target_include_directories(tls_stream PUBLIC include)
target_link_libraries(tls_stream PUBLIC mbedtls mbedx509 mbedcrypto)
target_compile_options(tls_stream PRIVATE -Wall -Wextra -Werror -Wpedantic)

add_executable(tls_probe src/probe.c tests/pressure.c tests/connect.c tests/sessions.c tests/security.c
    tests/allocations.c tests/records.c tests/boundaries.c tests/throughput.c
    platform/tap_network.c platform/lwip_transport.c platform/lwip_dns.c)
target_link_options(tls_probe PRIVATE "LINKER:--wrap=calloc" "LINKER:--wrap=free")
target_include_directories(tls_probe PRIVATE platform tests)
target_link_libraries(tls_probe PRIVATE tls_stream lwip)
target_compile_options(tls_probe PRIVATE -Wall -Wextra -Werror -Wpedantic)
