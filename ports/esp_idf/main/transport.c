#include "transport.h"
#include "lwip_dns.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include <errno.h>
#include <time.h>

static int64_t now_ms(void *context)
{
    (void)context;
    return esp_timer_get_time() / 1000;
}

static bool cancelled(void *context)
{
    return atomic_load(&((idf_transport *)context)->cancel_requested);
}

static bool time_ready(void *context)
{
    return ((idf_transport *)context)->clock_ready && time(NULL) >= 1577836800;
}

static int entropy(void *context, unsigned char *bytes, size_t length)
{
    (void)context;
    /* Emulator RNG only. This does not qualify hardware entropy without RF. */
    esp_fill_random(bytes, length);
    return 0;
}

static int trust(void *context, mbedtls_ssl_config *config)
{
    mbedtls_ssl_conf_ca_chain(config, &((idf_transport *)context)->roots, NULL);
    return 0;
}

static bool wait_socket(idf_transport *transport, bool write, int64_t deadline)
{
    while (!cancelled(transport)) {
        int64_t left = deadline - now_ms(NULL);
        if (left <= 0) return false;
        fd_set set;
        FD_ZERO(&set);
        FD_SET(transport->socket_fd, &set);
        struct timeval timeout = {0, (left < 10 ? left : 10) * 1000};
        int ready = lwip_select(transport->socket_fd + 1, write ? NULL : &set,
                                write ? &set : NULL, NULL, &timeout);
        if (ready > 0) return !cancelled(transport) && now_ms(NULL) < deadline;
        if (ready < 0 && errno != EINTR) return false;
    }
    return false;
}

typedef struct { idf_transport *transport; int64_t deadline; } open_budget;

static uint32_t remaining_ms(void *argument)
{
    open_budget *budget = argument;
    int64_t left = budget->deadline - now_ms(NULL);
    return cancelled(budget->transport) || left <= 0 ? 0 : (uint32_t)left;
}

static int open_socket(void *context, const char *host, uint16_t port, uint32_t budget)
{
    idf_transport *transport = context;
    ++transport->open_calls;
    int64_t deadline = now_ms(NULL) + budget;
    open_budget operation = {transport, deadline};
    ip_addr_t resolved;
    if (!remaining_ms(&operation)) return -1;
    /* Literals need no resolver slot, including when the DNS pool is full. */
    if (!ipaddr_aton(host, &resolved) && lwip_dns_resolve(host, &resolved, remaining_ms, &operation)) return -1;
    if (!IP_IS_V4(&resolved) || !remaining_ms(&operation)) return -1;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = ip4_addr_get_u32(ip_2_ip4(&resolved));
    transport->socket_fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
    int fd = transport->socket_fd;
    struct linger abort_on_close = {1, 0};
    if (fd < 0 || lwip_setsockopt(fd, SOL_SOCKET, SO_LINGER, &abort_on_close, sizeof(abort_on_close)) ||
        lwip_fcntl(fd, F_SETFL, O_NONBLOCK)) return -1;
    int result = lwip_connect(fd, (struct sockaddr *)&address, sizeof(address));
    if (result < 0 && errno == EINPROGRESS && wait_socket(transport, true, deadline)) {
        int error = 0;
        socklen_t size = sizeof(error);
        result = lwip_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size);
        if (error) result = -1;
    }
    return result;
}

static int receive_bytes(void *context, uint8_t *bytes, size_t length, uint32_t budget)
{
    idf_transport *transport = context;
    if (!wait_socket(transport, false, now_ms(NULL) + budget)) return -1;
    return lwip_recv(transport->socket_fd, bytes, length, 0);
}

static int send_bytes(void *context, const uint8_t *bytes, size_t length, uint32_t budget)
{
    idf_transport *transport = context;
    if (!wait_socket(transport, true, now_ms(NULL) + budget)) return -1;
    return lwip_send(transport->socket_fd, bytes, length, 0);
}

static void close_socket(void *context)
{
    idf_transport *transport = context;
    if (transport->socket_fd >= 0) {
        lwip_close(transport->socket_fd);
        transport->socket_fd = -1;
    }
}

int idf_transport_init(idf_transport *transport, const unsigned char *pem, size_t length)
{
    transport->socket_fd = -1;
    transport->clock_ready = false;
    transport->open_calls = 0;
    atomic_init(&transport->cancel_requested, false);
    mbedtls_x509_crt_init(&transport->roots);
    return mbedtls_x509_crt_parse(&transport->roots, pem, length);
}

tls_stream_port idf_transport_port(idf_transport *transport)
{
    return (tls_stream_port){.context = transport, .now_ms = now_ms,
        .time_ready = time_ready, .cancelled = cancelled, .entropy = entropy,
        .trust = trust, .open = open_socket, .read = receive_bytes,
        .write = send_bytes, .close = close_socket};
}

void idf_transport_destroy(idf_transport *transport)
{
    close_socket(transport);
    mbedtls_x509_crt_free(&transport->roots);
}
