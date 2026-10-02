#include "tap_network.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "lwip/tcpip.h"
#include "lwip/etharp.h"
#include "lwip/dns.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <unistd.h>

static int tap_fd = -1;
static struct netif interface;
static uint32_t rx_packets, tx_packets;

unsigned int lwip_port_rand(void)
{
    unsigned int value;
    if (getrandom(&value, sizeof(value), 0) != sizeof(value)) {
        abort();
    }
    return value;
}

int tap_network_open(const char *name)
{
    struct ifreq request = {0};
    if (strlen(name) >= IFNAMSIZ || tap_fd >= 0) {
        return -1;
    }
    tap_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (tap_fd < 0) {
        return -1;
    }
    request.ifr_flags = IFF_TAP | IFF_NO_PI;
    memcpy(request.ifr_name, name, strlen(name) + 1);
    if (ioctl(tap_fd, TUNSETIFF, &request) < 0) {
        tap_network_close();
        return -1;
    }
    return 0;
}

static err_t transmit(struct netif *netif, struct pbuf *packet)
{
    unsigned char frame[1514];
    (void)netif;
    if (packet->tot_len > sizeof(frame)) {
        return ERR_BUF;
    }
    pbuf_copy_partial(packet, frame, packet->tot_len, 0);
    if (write(tap_fd, frame, packet->tot_len) != packet->tot_len) {
        return ERR_IF;
    }
    ++tx_packets;
    return ERR_OK;
}

static err_t initialize_interface(struct netif *netif)
{
    static const unsigned char address[] = {0x02, 0, 0, 0, 0, 2};
    netif->name[0] = 't';
    netif->name[1] = 'p';
    netif->output = etharp_output;
    netif->linkoutput = transmit;
    netif->mtu = 1500;
    netif->hwaddr_len = sizeof(address);
    memcpy(netif->hwaddr, address, sizeof(address));
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

static void initialize_stack(void *context)
{
    ip4_addr_t address, mask, gateway;
    ip_addr_t dns;
    IP4_ADDR(&address, 192, 0, 2, 2);
    IP4_ADDR(&mask, 255, 255, 255, 252);
    IP4_ADDR(&gateway, 192, 0, 2, 1);
    configASSERT(netif_add(&interface, &address, &mask, &gateway, NULL,
                          initialize_interface, tcpip_input));
    netif_set_default(&interface);
    netif_set_up(&interface);
    IP_ADDR4(&dns, 192, 0, 2, 1);
    dns_setserver(0, &dns);
    xSemaphoreGive((SemaphoreHandle_t)context);
}

static void receive_task(void *context)
{
    unsigned char frame[1514];
    (void)context;
    for (;;) {
        ssize_t length = read(tap_fd, frame, sizeof(frame));
        if (length > 0) {
            struct pbuf *packet = pbuf_alloc(PBUF_RAW, (u16_t)length, PBUF_POOL);
            if (packet) {
                if (pbuf_take(packet, frame, (u16_t)length) != ERR_OK ||
                    interface.input(packet, &interface) != ERR_OK) {
                    pbuf_free(packet);
                } else {
                    ++rx_packets;
                }
            }
        } else if (length < 0 && errno != EAGAIN && errno != EINTR) {
            abort();
        }
        /* A bounded batch leaves time for other tasks even under load. */
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

void tap_network_start(void)
{
    SemaphoreHandle_t ready = xSemaphoreCreateBinary();
    configASSERT(ready);
    tcpip_init(initialize_stack, ready);
    configASSERT(xSemaphoreTake(ready, pdMS_TO_TICKS(5000)) == pdTRUE);
    vSemaphoreDelete(ready);
    configASSERT(xTaskCreate(receive_task, "tap-rx", 4096, NULL, 2, NULL) == pdPASS);
}

void tap_network_counts(uint32_t *received, uint32_t *sent)
{
    taskENTER_CRITICAL();
    *received = rx_packets;
    *sent = tx_packets;
    taskEXIT_CRITICAL();
}

void tap_network_close(void)
{
    if (tap_fd >= 0) {
        close(tap_fd);
        tap_fd = -1;
    }
}
