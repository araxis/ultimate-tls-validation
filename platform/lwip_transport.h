#ifndef TLS_LAB_LWIP_TRANSPORT_H
#define TLS_LAB_LWIP_TRANSPORT_H
#include "tls_stream.h"
#include "mbedtls/x509_crt.h"
#include <stdatomic.h>
typedef struct {
    int socket_fd;
    mbedtls_x509_crt roots;
    bool clock_ready;
    bool entropy_ready;
    atomic_bool cancel_requested;
} lwip_transport;
int lwip_transport_init(lwip_transport *, const char *ca_file);
tls_stream_port lwip_transport_port(lwip_transport *);
void lwip_transport_destroy(lwip_transport *);
/* May be called by another task while the owning task is in an operation.
 * The caller must join that task before destroying the transport. */
void lwip_transport_cancel(lwip_transport *);
#endif
