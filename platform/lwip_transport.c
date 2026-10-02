#include "lwip_transport.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
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

static int wait_socket(int fd, bool writing, uint32_t milliseconds)
{
    fd_set descriptors;
    FD_ZERO(&descriptors);
    FD_SET(fd, &descriptors);
    struct timeval timeout = {milliseconds / 1000, (milliseconds % 1000) * 1000};
    return lwip_select(fd + 1, writing ? NULL : &descriptors,
                       writing ? &descriptors : NULL, NULL, &timeout) == 1 ? 0 : -1;
}

static int open_socket(void *context, const char *host, uint16_t port, uint32_t budget)
{
    lwip_transport *transport = context;
    struct addrinfo hints = {0}, *address = NULL;
    int64_t start = now_ms(context);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    /* lwIP DNS retries are bounded by lwipopts.h. Check the overall budget
     * again before creating a socket; later fault tests qualify cancellation. */
    if (lwip_getaddrinfo(host, NULL, &hints, &address)) return -1;
    int64_t elapsed = now_ms(context) - start;
    if (elapsed < 0 || elapsed >= budget) {
        lwip_freeaddrinfo(address);
        return -1;
    }
    ((struct sockaddr_in *)address->ai_addr)->sin_port = htons(port);
    transport->socket_fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
    int fd = transport->socket_fd;
    int result = -1;
    /* Destroy is abortive and bounded, including partially connected sockets. */
    struct linger abort_on_close = {1, 0};
    if (fd >= 0 && lwip_setsockopt(fd, SOL_SOCKET, SO_LINGER, &abort_on_close,
                                 sizeof(abort_on_close)) == 0 &&
        lwip_fcntl(fd, F_SETFL, O_NONBLOCK) == 0) {
        result = lwip_connect(fd, address->ai_addr, address->ai_addrlen);
        if (result < 0 && errno == EINPROGRESS &&
            wait_socket(fd, true, budget - (uint32_t)elapsed) == 0) {
            int error = 0;
            socklen_t size = sizeof(error);
            result = lwip_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size);
            if (error) result = -1;
        }
    }
    lwip_freeaddrinfo(address);
    return result;
}

static int receive_bytes(void *context, uint8_t *bytes, size_t length, uint32_t budget)
{
    int fd = ((lwip_transport *)context)->socket_fd;
    if (wait_socket(fd, false, budget)) return -1;
    return (int)lwip_recv(fd, bytes, length, 0);
}

static int send_bytes(void *context, const uint8_t *bytes, size_t length, uint32_t budget)
{
    int fd = ((lwip_transport *)context)->socket_fd;
    if (wait_socket(fd, true, budget)) return -1;
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
    mbedtls_x509_crt_init(&transport->roots);
    return mbedtls_x509_crt_parse_file(&transport->roots, ca_file);
}

tls_stream_port lwip_transport_port(lwip_transport *transport)
{
    return (tls_stream_port){
        .context = transport, .now_ms = now_ms, .time_ready = time_ready,
        .entropy = entropy, .trust = trust, .open = open_socket,
        .read = receive_bytes, .write = send_bytes, .close = close_socket
    };
}

void lwip_transport_destroy(lwip_transport *transport)
{
    close_socket(transport);
    mbedtls_x509_crt_free(&transport->roots);
}
