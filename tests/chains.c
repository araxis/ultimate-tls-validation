#include "chains.h"
#include "allocations.h"
#include "lwip_transport.h"
#include "FreeRTOS.h"
#include <stdio.h>

static void check(struct chain_results *r, bool passed, const char *label)
{
    ++r->checks;
    if (!passed) ++r->failures;
    printf("%s chains: %s\n", passed ? "PASS" : "FAIL", label);
}

struct chain_results chain_tests(const char *ca_path)
{
    struct chain_results result = {0};
    for (unsigned index = 0; index < 16; ++index) {
        unsigned profile = (index % 8) / 2;
        allocation_measure_begin();
        lwip_transport transport;
        configASSERT(lwip_transport_init(&transport, ca_path) == 0);
        tls_stream_port port = lwip_transport_port(&transport);
        tls_stream *stream = tls_stream_create(&port);
        configASSERT(stream);
        struct allocation_measurement prepared = allocation_measure_read();
        allocation_measure_phase();
        tls_status status = tls_stream_open(stream, "tls.lab.test", (uint16_t)(8480 + profile), 7000);
        struct allocation_measurement handshake = allocation_measure_read();
        check(&result, status == TLS_OK && tls_stream_diagnostic(stream).verify_flags == 0,
              "complete certificate chain authenticated");
        check(&result, handshake.phase_peak >= handshake.bytes && handshake.peak >= prepared.peak,
              "handshake live and peak accounting is consistent");
        allocation_measure_phase();
        uint8_t trigger = (uint8_t)index;
        check(&result, tls_stream_write(stream, &trigger, 1) == 1, "transfer request sent");
        uint8_t bytes[512];
        size_t total = 0;
        bool exact = true;
        int count;
        while ((count = tls_stream_read(stream, bytes, sizeof(bytes))) > 0) {
            for (int i = 0; i < count; ++i) {
                if (bytes[i] != (uint8_t)((total + (size_t)i) * 37U + 11U)) exact = false;
            }
            total += (size_t)count;
            if (total > 65536) break;
        }
        struct allocation_measurement transfer = allocation_measure_read();
        check(&result, exact && total == 65536, "complete exact payload across record sizes");
        check(&result, count == 0 && tls_stream_status(stream) == TLS_OK, "authenticated EOF");
        check(&result, transfer.peak >= handshake.peak && transfer.phase_peak >= handshake.bytes,
              "phase accounting retains the lifetime peak");
        tls_stream_destroy(stream);
        check(&result, transport.socket_fd == -1, "socket released");
        lwip_transport_destroy(&transport);
        struct allocation_measurement final = allocation_measure_end();
        check(&result, final.live == 0 && final.bytes == 0 && final.rejected == 0,
              "all tracked certificate and TLS allocations freed without injection");
        printf("RESULT chain index=%u profile=%u record=%u bytes=%zu prepared=%zu prepared_peak=%zu"
               " handshake_live=%zu handshake_peak=%zu transfer_live=%zu transfer_peak=%zu lifetime_peak=%zu"
               " final_live=%u final_bytes=%zu\n", index, profile, index % 2 ? 16384 : 512, total,
               prepared.bytes, prepared.peak, handshake.bytes, handshake.phase_peak,
               transfer.bytes, transfer.phase_peak, final.peak, final.live, final.bytes);
    }
    return result;
}
