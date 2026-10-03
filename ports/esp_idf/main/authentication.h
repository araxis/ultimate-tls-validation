#ifndef TLS_LAB_AUTHENTICATION_H
#define TLS_LAB_AUTHENTICATION_H
#include <stdbool.h>

void authentication_probe(bool ready, void (*check)(bool, const char *));
void authentication_recovery(const char *label, bool ready, void (*check)(bool, const char *));
#endif
