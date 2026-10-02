#ifndef TLS_LAB_STREAM_H
#define TLS_LAB_STREAM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mbedtls/ssl.h"

typedef enum {
    TLS_OK, TLS_INVALID_ARGUMENT, TLS_CANCELLED, TLS_TIMEOUT,
    TLS_TRANSPORT_ERROR, TLS_ERROR, TLS_TIME_UNAVAILABLE, TLS_TRUNCATED
} tls_status;

/* Trusted platform callbacks. Operations must honor the remaining deadline.
 * read/write accept short transfers; read returns zero only for transport EOF.
 * close is bounded and safe after a partially failed open. entropy fills the
 * entire requested buffer with cryptographic entropy and returns zero on success.
 * time_ready qualifies the same UTC clock Mbed TLS uses for certificate dates.
 * trust attaches roots; it must not suppress certificate verification.
 * The caller keeps callback context alive until destroy returns.
 */
typedef struct {
    void *context;
    int64_t (*now_ms)(void *);
    bool (*time_ready)(void *);
    bool (*cancelled)(void *);
    int (*entropy)(void *, unsigned char *, size_t);
    int (*trust)(void *, mbedtls_ssl_config *);
    int (*open)(void *, const char *, uint16_t, uint32_t);
    int (*read)(void *, uint8_t *, size_t, uint32_t);
    int (*write)(void *, const uint8_t *, size_t, uint32_t);
    void (*close)(void *);
} tls_stream_port;

typedef struct tls_stream tls_stream;
typedef enum {
    TLS_STAGE_VALIDATE, TLS_STAGE_TIME, TLS_STAGE_RANDOM, TLS_STAGE_CONFIG,
    TLS_STAGE_TRUST, TLS_STAGE_SETUP, TLS_STAGE_HOSTNAME, TLS_STAGE_TCP_OPEN,
    TLS_STAGE_HANDSHAKE, TLS_STAGE_READ, TLS_STAGE_WRITE
} tls_stage;
typedef struct {
    tls_stage stage;
    tls_status status;
    int code;
    uint32_t verify_flags;
} tls_stream_diagnostics;

/* One connection per instance, owned by one task. Carries arbitrary bytes.
 * One total deadline covers open and subsequent reads/writes. destroy releases
 * the transport and all TLS state on success or failure; no implicit retry.
 * DNS hostnames/IPv4 literals only in this initial validation implementation.
 */
tls_stream *tls_stream_create(const tls_stream_port *port);
tls_status tls_stream_open(tls_stream *, const char *host, uint16_t port, uint32_t timeout_ms);
int tls_stream_read(tls_stream *, uint8_t *, size_t);
int tls_stream_write(tls_stream *, const uint8_t *, size_t);
tls_status tls_stream_status(const tls_stream *);
tls_stream_diagnostics tls_stream_diagnostic(const tls_stream *);
void tls_stream_destroy(tls_stream *);
#endif
