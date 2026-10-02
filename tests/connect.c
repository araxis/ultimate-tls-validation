#include "connect.h"
#include "lwip_transport.h"
#include "lwip_dns.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/stats.h"
#include "lwip/memp.h"
#include <stdio.h>

static struct connect_results results;

static void check(bool passed, const char *label)
{
    ++results.checks;
    if (!passed) ++results.failures;
    printf("%s %s\n", passed ? "PASS" : "FAIL", label);
}

/* Only the core task accesses this fixture while installed. Callbacks provide
 * barriers before inspection or destruction of its semaphore and saved output. */
static struct {
    netif_linkoutput_fn original;
    SemaphoreHandle_t syn_seen;
    uint16_t port;
    unsigned syns, drops;
    bool discard;
} link_fault;

static err_t fault_output(struct netif *interface, struct pbuf *packet)
{
    uint8_t header[128];
    unsigned copied = pbuf_copy_partial(packet, header, sizeof(header), 0);
    if (copied >= 54 && header[12] == 8 && header[13] == 0 &&
        (header[14] >> 4) == 4 && header[23] == 6 &&
        header[30] == 192 && header[31] == 0 && header[32] == 2 && header[33] == 1) {
        unsigned tcp = 14 + (header[14] & 15U) * 4;
        if (tcp >= 34 && copied >= tcp + 20 &&
            ((unsigned)header[tcp + 2] * 256 + header[tcp + 3]) == link_fault.port &&
            (header[tcp + 13] & 0x12) == 0x02) {
            ++link_fault.syns;
            xSemaphoreGive(link_fault.syn_seen);
            if (link_fault.discard) {
                ++link_fault.drops;
                return ERR_OK;
            }
        }
    }
    return link_fault.original(interface, packet);
}

struct snapshot {
    SemaphoreHandle_t done;
    unsigned connections, pcbs, segments;
    bool install;
};

static void configure_link(void *context)
{
    struct snapshot *snapshot = context;
    configASSERT(netif_default && netif_default->name[0] == 't' && netif_default->name[1] == 'p');
    if (snapshot->install) {
        configASSERT(!link_fault.original);
        link_fault.original = netif_default->linkoutput;
        netif_default->linkoutput = fault_output;
    } else {
        configASSERT(netif_default->linkoutput == fault_output);
        netif_default->linkoutput = link_fault.original;
        link_fault.original = NULL;
    }
    snapshot->connections = lwip_stats.memp[MEMP_NETCONN]->used;
    snapshot->pcbs = lwip_stats.memp[MEMP_TCP_PCB]->used;
    snapshot->segments = lwip_stats.memp[MEMP_TCP_SEG]->used;
    xSemaphoreGive(snapshot->done);
}

static struct snapshot change_link(bool install)
{
    struct snapshot snapshot = {.done = xSemaphoreCreateBinary(), .install = install};
    configASSERT(snapshot.done);
    configASSERT(tcpip_callback(configure_link, &snapshot) == ERR_OK);
    configASSERT(xSemaphoreTake(snapshot.done, pdMS_TO_TICKS(1000)) == pdTRUE);
    vSemaphoreDelete(snapshot.done);
    snapshot.done = NULL;
    return snapshot;
}

struct cancellation {
    lwip_transport *transport;
    tls_stream_port port;
    SemaphoreHandle_t done;
    bool observed_syn;
    int64_t cancelled_ms;
};

static void cancel_connect(void *context)
{
    struct cancellation *request = context;
    request->observed_syn = xSemaphoreTake(link_fault.syn_seen, pdMS_TO_TICKS(1000)) == pdTRUE;
    if (request->observed_syn) {
        vTaskDelay(pdMS_TO_TICKS(50));
        request->cancelled_ms = request->port.now_ms(request->transport);
        lwip_transport_cancel(request->transport);
    }
    xSemaphoreGive(request->done);
    vTaskDelete(NULL);
}

static void connection_fault(const char *ca_path, const char *label, bool discard, bool cancel)
{
    link_fault.port = discard ? 8449 : 8448;
    link_fault.discard = discard;
    link_fault.syns = link_fault.drops = 0;
    link_fault.syn_seen = xSemaphoreCreateBinary();
    configASSERT(link_fault.syn_seen);
    struct snapshot before = change_link(true);
    lwip_transport transport;
    configASSERT(lwip_transport_init(&transport, ca_path) == 0);
    tls_stream_port port = lwip_transport_port(&transport);
    tls_stream *stream = tls_stream_create(&port);
    configASSERT(stream);
    struct cancellation request = {.transport = &transport, .port = port};
    if (cancel) {
        request.done = xSemaphoreCreateBinary();
        configASSERT(request.done);
        configASSERT(xTaskCreate(cancel_connect, "connect-cancel", 4096, &request, 2, NULL) == pdPASS);
    }
    int64_t start = port.now_ms(&transport);
    tls_status status = tls_stream_open(stream, "tls.lab.test", link_fault.port, cancel ? 5000 : discard ? 200 : 1000);
    int64_t finished = port.now_ms(&transport);
    tls_stream_diagnostics diagnostic = tls_stream_diagnostic(stream);
    if (cancel) {
        configASSERT(xSemaphoreTake(request.done, pdMS_TO_TICKS(1500)) == pdTRUE);
        vSemaphoreDelete(request.done);
        check(request.observed_syn, "cancellation follows an emitted SYN");
    }
    check(status == (cancel ? TLS_CANCELLED : discard ? TLS_TIMEOUT : TLS_TRANSPORT_ERROR), label);
    check(diagnostic.stage == TLS_STAGE_TCP_OPEN, "failure occurs during TCP connection setup");
    int64_t elapsed = finished - (cancel ? request.cancelled_ms : start);
    check(elapsed >= 0 && elapsed <= (discard && !cancel ? 450 : 250), "connection failure return bounded");
    if (discard && !cancel) check(elapsed >= 200, "stalled connection honors requested deadline");
    check(transport.socket_fd == -1, "failed open releases socket before destroy");
    tls_stream_destroy(stream);
    check(transport.socket_fd == -1, "destroy after failed open is safe");
    lwip_transport_destroy(&transport);
    struct snapshot after = change_link(false);
    check(link_fault.syns > 0, "connection attempt emitted TCP SYN");
    check(discard ? link_fault.drops == link_fault.syns : link_fault.drops == 0,
          "only selected stalled connection SYNs discarded");
    check(before.connections == after.connections, "connection netconn pool restored");
    check(before.pcbs == after.pcbs, "connection TCP PCB pool restored");
    check(before.segments == after.segments, "connection TCP segment pool restored");
    check(lwip_dns_pending() == 0, "no pending DNS lookup after connection failure");
    printf("RESULT %s status=%d stage=%d syns=%u drops=%u elapsed_ms=%lld total_ms=%lld\n",
           label, status, diagnostic.stage, link_fault.syns, link_fault.drops,
           (long long)elapsed, (long long)(finished - start));
    vSemaphoreDelete(link_fault.syn_seen);
    link_fault.syn_seen = NULL;
}

struct connect_results connect_tests(const char *ca_path)
{
    results = (struct connect_results){0};
    connection_fault(ca_path, "connect-refused", false, false);
    connection_fault(ca_path, "connect-timeout", true, false);
    connection_fault(ca_path, "connect-cancel", true, true);
    return results;
}
