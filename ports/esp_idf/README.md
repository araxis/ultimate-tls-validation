# ESP32-S3 emulator probe

A separate ESP-IDF application compiles the same `src/tls_stream.c` and public
header as the host reference. Its small test adapter accepts IPv4 literals and
hostnames through the shared bounded asynchronous DNS resolver.
The default smoke test exercises one verified RSA exchange, exact request/response
bytes, authenticated EOF, socket cleanup and advancing FreeRTOS ticks. Optional
RSA and P-256 ECDSA profiles test authentication rejection and recovery. These
tests do not qualify wider concurrency, Wi-Fi or physical hardware. A separate
timing profile covers selected handshake/read deadlines and cancellation.
A socket-wait profile adds connect refusal, connect waits and blocked writes.
A DNS profile exercises lookup lifetime, cancellation, capacity and recovery.

The peer is the existing Python TLS fixture on a private TAP subnet. Certificates
are generated per build with an IP subject alternative name and independently
verified by OpenSSL. The image embeds the test root and the host's fixture UTC;
the runner rejects fixtures older than one hour. Normal certificate checks remain
enabled. Test clock provisioning and emulated RNG do not establish production
clock trust or physical entropy quality. The guest has no default gateway.

## Build and run

Use ESP-IDF 5.3.6 and its installed Python/tool environment, plus Espressif QEMU
`esp-develop-9.2.2-20260417` with the `esp32s3` machine and `open_eth` model.
The normal Linux/WSL user builds; only TAP setup requires root. The wrapper drops
privileges before launching the guest and peer and removes the interface afterward.
Do not run this alongside the host probe, which uses the same private interface.

```sh
python3 ports/esp_idf/prepare.py \
  --sdk /path/to/esp-idf-5.3.6 \
  --tools /path/to/installed-idf-tools \
  --idf-python /path/to/idf-python-environment/bin/python

sudo python3 ports/esp_idf/run.py --uid "$(id -u)" \
  --evidence /absolute/path/printed/by/prepare \
  --qemu /path/to/qemu/bin/qemu-system-xtensa
```

Preparation writes a fresh source archive, input hashes, fixture, build log,
configuration, ELF/map and merged image under ignored `evidence/`. Build products
stay in a fresh local cache directory. The component references the original TLS
source directly; no separate copy is maintained.

The runner checks artifact hashes and uses snapshot mode so execution cannot
write back to the saved image. It preserves guest logs, peer events, emulator and
image hashes, complete check counts and failures. Success requires exactly ten
guest checks, the expected run identity, one independently verified peer request,
the required TLS suite and a clean return from the app. The wrapper then terminates
the idle emulator; that termination is not represented as a guest exit code.

Prepare a new fixture for every attempt, including after failure; existing run
results are never overwritten. No serial device or flashing command is used.

## Authentication rejection and recovery

Add `--authentication rsa` or `--authentication ecdsa` to the preparation command.
Run each fresh image with the same runner; it reads the profile from the saved
build result. The default command remains the ten-check smoke test.

Each authentication profile requires 83 checks across nine ordered attempts:

1. Valid chain and exact exchange.
2. Wrong IP identity, then a successful fresh connection.
3. Untrusted root, then a successful fresh connection.
4. Clock unavailable, then a successful fresh connection.
5. Entropy callback failure, then a successful fresh connection.

Each rejected attempt checks the exact public status, stage, library error and
certificate flags. Subsequent reads/writes must fail, the caller's read buffer
must remain unchanged, and the failure diagnostic must remain stable. Socket
release is checked after failed open and after destruction. A test-adapter counter
proves clock and entropy failures occur without invoking transport open.

The independent server requires five exact requests, seven matching server-name
events, a bad-certificate alert for the wrong identity, and an unknown-CA alert
for the untrusted root. Unexpected events or missing/duplicate guest results fail
the run. Both certificate profiles are independently checked with OpenSSL before
building, including exact IP-mismatch and untrusted-root rejection. ECDSA uses a
binary response body to exercise embedded zero and high-bit bytes.

These cases use directly signed RSA-2048 or P-256 certificates. They do not cover
expired/future certificates, intermediates, mixed algorithms, other curves,
allocation failures or long-run resource retention on this port. Entropy failure
is injected into the port callback; it does not assess the physical RNG. Recovery
means a new stream/context after destruction, not reuse of a failed handle.

## Finite waits and recovery

Add `--timing` to preparation for a separate RSA profile with 91 checks across
four failure cases and four fresh-connection recoveries. This option cannot be
combined with `--authentication`.

The controlled peer stalls either the handshake or the response read. Each
operation must end on its overall deadline or cancellation from a second
FreeRTOS task. Cancellation is armed when the selected transport read callback
starts; the worker waits five 10 ms ticks before setting the atomic cancellation
flag. The test joins that worker before releasing its context.

Handshake timeout uses 1500 ms; response-read timeout uses 3000 ms starting at
open. The read test adds a deliberate 500 ms delay after the request, which must
consume that original budget. Deadline completion allows 250 ms scheduling
tolerance; cancellation must return within 250 ms after its signal and before
the 10-second overall budget. These guest-clock tolerances are acceptance checks,
not device latency guarantees. Tick alignment can make the five-tick delay
shorter than 50 ms; the check requires at least 40 ms.

All failures require exact status/stage/error diagnostics, closed sockets,
refused subsequent I/O, unchanged read buffers and stable diagnostics. Aborted
handshakes must report certificate verification unavailable (`UINT32_MAX`), while
reads start after successful verification and retain zero verification flags.
Recovery uses the same verified byte-exchange checks as the authentication suite.
The peer independently requires two handshake stalls, two read stalls, six exact
requests and six matching server-name events with the required RSA suite.

This profile does not cover connect/DNS waits, blocked writes, completion races,
ECDSA-specific timing, simultaneous connections or task/heap resource budgets.

## Connection waits and blocked writes

Add `--socket-waits` to preparation for a separate RSA profile with 122 checks.
It is mutually exclusive with the other profiles. Five failure cases each have
a fresh authenticated recovery: TCP refusal, connect timeout/cancellation, and
blocked-write timeout/cancellation. The TLS core and socket adapter are unchanged.

A test-only network-output hook counts connection SYNs. It drops only SYNs to
the selected stall port, while refusal targets an unbound port. Hook installation
and restoration run on the lwIP core with a completion barrier. Cancellation is
triggered by an observed SYN or a non-writable socket, followed by five RTOS ticks;
the worker is joined before releasing its context. Write tests authenticate first,
wait for a peer-ready byte and send 512-byte chunks to a peer that stops consuming
data. They require actual backpressure, positive progress below a 256 KiB cap,
the exact terminal diagnostic, refused later I/O, socket release and recovery.

Connect refusal allows 500 ms. Connect timeout uses 1500 ms; write timeout uses
4000 ms including the handshake. Deadlines allow 250 ms scheduling tolerance.
Cancellation must return within 250 ms of its signal and before the 10-second
overall budget. These are emulator acceptance limits, not hardware guarantees.

The peer independently requires five exact TLS 1.2 RSA exchanges, seven matching
server-name events and two write stalls with unread ciphertext. It records whether
closure was observed during the stall. If not, after six seconds it sends a
one-byte application probe without draining the receive queue, then requires a
close indication within one second. The runner keeps the idle guest alive for
this bounded check. Local release and immediate remote notification are distinct:
an abort reset after a zero-window probe can carry a sequence number ahead of the
peer's expected value and be ignored. A subsequent peer probe can elicit a valid
reset from the released endpoint. This test does not promise immediate remote
closure or reliable delivery of all bytes accepted before failure. See
[TCP reset validation](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4).

The original passive-close failures remain in the local evidence; the corrected
fixture verifies post-deadline cleanup explicitly. No dependency is patched to
alter reset behavior. DNS, exhaustive races, ECDSA timing, repeated resource
retention and target stack/heap budgets remain separate work.

## DNS ownership and shared deadlines

Add `--dns-waits` to preparation for a separate 154-check RSA profile. The guest
uses the private peer as its only configured DNS server. Like the host reference,
the test application compiles lwIP with `DNS_SERVER_PORT=1053`, allowing the peer
to run unprivileged. This fixture setting does not change any installed firmware.

`platform/lwip_dns.c` is compiled directly into both ports. Its four-slot pool
owns copied names and results until the waiting task and eventual callback have
both released their references. Cancellation or timeout releases the caller's
reference without handing caller buffers to a late callback. ESP-IDF uses a
shared critical-section spinlock across cores; the host retains its existing
critical sections. Both request IPv4 explicitly. Polling waits at least one RTOS
tick instead of repeatedly yielding when less than one tick remains.

The adapter bypasses this pool for IP literals and shares one deadline across
DNS and TCP connect; the TLS stream retains its overall operation deadline.
Resolving an address does not replace the hostname used for certificate checks.
The profile verifies:

- A hostname exchange, negative DNS response and wrong certificate identity.
- A 100 ms DNS deadline and cancellation from a second task, followed by replies
  delayed by 600 ms. Caller contexts are destroyed before the callback drains.
- A 600 ms DNS delay followed by a stalled handshake, with total completion in
  1000–1250 ms. Resetting the budget after resolution would fail this check.
- Four 60 ms abandoned lookups retaining exactly four slots until delayed replies
  arrive, prompt rejection of a fifth lookup, and an authenticated IP-literal
  connection while those slots remain occupied.
- Draining late callbacks back to zero slots and fresh hostname recovery.

The independent peer checks IPv4 queries, bounded retry counts, expected replies,
server names, a certificate alert, a handshake stall and eight exact exchanges.
There must be no query for the rejected fifth lookup. Guest diagnostics, retained
slot counts, ordered attempts and final cleanup must all agree. Scheduling
tolerances describe emulator acceptance, not physical latency guarantees.

This is selected DNS lifetime coverage. CNAME chains, IPv6, server failover,
malformed replies, simultaneous callers, all resolver/core-queue races and natural
retry exhaustion are not newly qualified on ESP-IDF. A retained slot is bounded
state, not proof that all DNS/kernel allocations have been measured or freed.

## Boundaries

The adapter has nonblocking lwIP socket operations with a bounded wait budget.
Cancellation is tested in selected DNS, connect, handshake, read and write cases.
Wider concurrency and target resource accounting remain separate validation.
The app uses IDF's own kernel and network configuration, not the host simulator's
headers. Its 12 KiB main-task allocation is a test setting, not a proven minimum
stack size. No total heap, leak-freedom, hardware timing or device headroom claim
follows from these tests.
