#ifndef TLS_LAB_IDF_TRANSPORT_H
#define TLS_LAB_IDF_TRANSPORT_H
#include "tls_stream.h"
#include "mbedtls/x509_crt.h"
#include <stdatomic.h>

/* Test-port context, owned by the calling task and destroyed after the stream.
 * Initial feasibility accepts IPv4 literals only; no DNS coverage is claimed. */
typedef struct {
    int socket_fd;
    unsigned open_calls;
    bool clock_ready;
    atomic_bool cancel_requested;
    mbedtls_x509_crt roots;
} idf_transport;

int idf_transport_init(idf_transport *, const unsigned char *pem, size_t length);
tls_stream_port idf_transport_port(idf_transport *);
void idf_transport_destroy(idf_transport *);
#endif
