#ifndef TLS_LAB_IDF_SECURITY_H
#define TLS_LAB_IDF_SECURITY_H
#include <stdbool.h>
void security_probe(bool ready, void (*check)(bool, const char *));
#endif
