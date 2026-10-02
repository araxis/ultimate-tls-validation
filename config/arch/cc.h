#ifndef TLS_LAB_ARCH_CC_H
#define TLS_LAB_ARCH_CC_H
#include <errno.h>
#include <stdint.h>
#include <sys/time.h>
#define LWIP_TIMEVAL_PRIVATE 0
#define LWIP_ERRNO_STDINCLUDE 1
#define LWIP_ERRNO_INCLUDE <errno.h>
unsigned int lwip_port_rand(void);
#define LWIP_RAND() lwip_port_rand()
#endif
