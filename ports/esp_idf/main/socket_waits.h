#ifndef TLS_LAB_SOCKET_WAITS_H
#define TLS_LAB_SOCKET_WAITS_H
#include <stdbool.h>
void socket_waits_probe(bool ready, void (*check)(bool, const char *));
#endif
