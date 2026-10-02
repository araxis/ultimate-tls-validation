#ifndef TLS_LAB_LWIPOPTS_H
#define TLS_LAB_LWIPOPTS_H
#define NO_SYS 0
#define SYS_LIGHTWEIGHT_PROT 1
#define MEM_ALIGNMENT 8
#define MEM_SIZE (128 * 1024)
#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_DNS 1
/* Private fixture port avoids running the DNS peer as root. */
#define DNS_SERVER_PORT 1053
#define LWIP_DHCP 0
#define LWIP_ARP 1
#define LWIP_NETCONN 1
#define LWIP_SOCKET 1
#define LWIP_COMPAT_SOCKETS 0
#define LWIP_POSIX_SOCKETS_IO_NAMES 0
#define LWIP_SO_RCVTIMEO 1
#define LWIP_SO_SNDTIMEO 1
#define LWIP_SO_LINGER 1
#define LWIP_SOCKET_SELECT 1
#define LWIP_TCPIP_CORE_LOCKING 0
#define LWIP_FREERTOS_CHECK_CORE_LOCKING 1
void sys_check_core_locking(void);
void sys_mark_tcpip_thread(void);
#define LWIP_ASSERT_CORE_LOCKED() sys_check_core_locking()
#define LWIP_MARK_TCPIP_THREAD() sys_mark_tcpip_thread()
#define TCPIP_THREAD_STACKSIZE 32768
#define TCPIP_THREAD_PRIO 3
#define TCPIP_MBOX_SIZE 32
#define DEFAULT_TCP_RECVMBOX_SIZE 16
#define DEFAULT_UDP_RECVMBOX_SIZE 8
#define DEFAULT_ACCEPTMBOX_SIZE 4
#define MEMP_NUM_NETCONN 8
#define MEMP_NUM_TCP_PCB 8
#define MEMP_NUM_TCP_SEG 64
#define PBUF_POOL_SIZE 64
#define TCP_MSS 1460
#define TCP_WND (8 * TCP_MSS)
#define TCP_SND_BUF (8 * TCP_MSS)
#define DNS_MAX_RETRIES 2
#define LWIP_STATS 1
#define LWIP_STATS_DISPLAY 0
#endif
