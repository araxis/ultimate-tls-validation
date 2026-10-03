#ifndef TLS_LAB_IDF_SESSIONS_H
#define TLS_LAB_IDF_SESSIONS_H
#include <stdbool.h>
void sessions_probe(bool ready, void (*check)(bool, const char *));
#endif
