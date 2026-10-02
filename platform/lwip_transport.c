#include "lwip_transport.h"
#include "lwip_dns.h"
#include "lwip/sockets.h"
#include <errno.h>
#include <sys/random.h>
#include <time.h>

static int64_t now_ms(void *context)
{
    struct timespec now;
    (void)context;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static bool time_ready(void *context)
{
    /* This reference port relies on the host's configured UTC clock. */
    return ((lwip_transport *)context)->clock_ready && time(NULL) >= 1577836800;
}

static bool cancelled(void *context)
{
    return atomic_load(&((lwip_transport *)context)->cancel_requested);
}

void lwip_transport_cancel(lwip_transport *transport)
{
    atomic_store(&transport->cancel_requested, true);
}

static int entropy(void *context, unsigned char *bytes, size_t length)
{
    if (!((lwip_transport *)context)->entropy_ready) return -1;
    while (length) {
        ssize_t count = getrandom(bytes, length, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        bytes += count;
        length -= (size_t)count;
    }
    return 0;
}

static int trust(void *context, mbedtls_ssl_config *config)
{
    mbedtls_ssl_conf_ca_chain(config, &((lwip_transport *)context)->roots, NULL);
    return 0;
}

struct operation {
    lwip_transport *transport;
    int64_t started_ms;
    uint32_t budget_ms;
};

static uint32_t remaining_ms(void *context)
{
    struct operation *operation = context;
    int64_t now = now_ms(NULL);
    if (cancelled(operation->transport) || now < operation->started_ms ||
        now - operation->started_ms >= operation->budget_ms) return 0;
    return operation->budget_ms - (uint32_t)(now - operation->started_ms);
}

static int wait_socket(int fd, bool writing, struct operation *operation)
{
    uint32_t left;
    while ((left = remaining_ms(operation)) != 0) {
        fd_set descriptors;
        FD_ZERO(&descriptors);
        FD_SET(fd, &descriptors);
        /* Poll cancellation between bounded waits, with one operation budget. */
        uint32_t slice = left < 10 ? left : 10;
        struct timeval timeout = {0, slice * 1000};
        int result = lwip_select(fd + 1, writing ? NULL : &descriptors,
                                writing ? &descriptors : NULL, NULL, &timeout);
        if (result > 0) return remaining_ms(operation) ? 0 : -1;
        if (result < 0 && errno != EINTR) return -1;
    }
    return -1;
}

static int open_socket(void *context, const char *host, uint16_t port, uint32_t budget)
{
    lwip_transport *transport = context;
    struct operation operation = {transport, now_ms(context), budget};
    ip_addr_t resolved;
    if (lwip_dns_resolve(host, &resolved, remaining_ms, &operation) ||
        !remaining_ms(&operation)) return -1;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = ip4_addr_get_u32(ip_2_ip4(&resolved));
    transport->socket_fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
    int fd = transport->socket_fd;
    int result = -1;
    /* Zero linger avoids waiting for unsent data. The stack may still retain
     * normal TCP closing/TIME_WAIT state after releasing the socket. */
    struct linger abort_on_close = {1, 0};
    if (fd >= 0 && lwip_setsockopt(fd, SOL_SOCKET, SO_LINGER, &abort_on_close,
                                 sizeof(abort_on_close)) == 0 &&
        lwip_fcntl(fd, F_SETFL, O_NONBLOCK) == 0) {
        result = lwip_connect(fd, (struct sockaddr *)&address, sizeof(address));
        if (result < 0 && errno == EINPROGRESS &&
            wait_socket(fd, true, &operation) == 0) {
            int error = 0;
            socklen_t size = sizeof(error);
            result = lwip_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size);
            if (error) result = -1;
        }
    }
    return result;
}

static int receive_bytes(void *context, uint8_t *bytes, size_t length, uint32_t budget)
{
    int fd = ((lwip_transport *)context)->socket_fd;
    struct operation operation = {context, now_ms(context), budget};
    if (wait_socket(fd, false, &operation)) return -1;
    return (int)lwip_recv(fd, bytes, length, 0);
}

static int send_bytes(void *context, const uint8_t *bytes, size_t length, uint32_t budget)
{
    int fd = ((lwip_transport *)context)->socket_fd;
    struct operation operation = {context, now_ms(context), budget};
    if (wait_socket(fd, true, &operation)) return -1;
    return (int)lwip_send(fd, bytes, length, 0);
}

static void close_socket(void *context)
{
    lwip_transport *transport = context;
    if (transport->socket_fd >= 0) {
        lwip_close(transport->socket_fd);
        transport->socket_fd = -1;
    }
}

int lwip_transport_init(lwip_transport *transport, const char *ca_file)
{
    transport->socket_fd = -1;
    transport->clock_ready = true;
    transport->entropy_ready = true;
    atomic_init(&transport->cancel_requested, false);
    mbedtls_x509_crt_init(&transport->roots);
    return mbedtls_x509_crt_parse_file(&transport->roots, ca_file);
}

tls_stream_port lwip_transport_port(lwip_transport *transport)
{
    return (tls_stream_port){
        .context = transport, .now_ms = now_ms, .time_ready = time_ready,
        .cancelled = cancelled,
        .entropy = entropy, .trust = trust, .open = open_socket,
        .read = receive_bytes, .write = send_bytes, .close = close_socket
    };
}

void lwip_transport_destroy(lwip_transport *transport)
{
    close_socket(transport);
    mbedtls_x509_crt_free(&transport->roots);
}
