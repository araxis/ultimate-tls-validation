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
A resource profile measures scoped allocations, global heap and observed task
stack headroom for successful and rejected RSA/P-256 connections.

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

## Scoped allocation and stack measurements

Add `--memory-accounting rsa` or `--memory-accounting ecdsa` to preparation.
Each separate profile requires 119 checks across four valid exchanges and four
wrong-identity rejections. It captures allocation, internal-heap, stack and TCP
state before setup, after root parsing, stream creation, open, destruction and
a 500 ms settling interval. At the end it waits up to 135 seconds for natural
TCP timer expiry. Neither timers nor allocation counters are reset to make
retained state disappear. Expect roughly two minutes per run.

Only this profile compiles the stream's allocation calls through a test meter
and wraps ESP-IDF's Mbed TLS allocator. Both forward to the unchanged allocators.
The verified SDK configuration uses internal 8-bit heap allocation. The meter
counts requested bytes on the main task; it excludes allocator metadata, other
tasks and unwrapped paths. Its 256-entry registry fails on overflow instead of
under-counting. The initial measurement's metadata occupied 4,125 bytes of linked
symbols, excluding alignment and code. The ordinary DNS regression verifies that these wrappers
and the resource probe are absent from its linked image.

Observed with ESP-IDF 5.3.6, 16,384-byte incoming and 4,096-byte outgoing TLS
buffers, directly signed RSA-2048 or P-256 certificates:

| Measurement (bytes) | RSA | P-256 ECDSA |
| --- | ---: | ---: |
| Tracked live allocation after successful open | 26,397 | 24,716 |
| Tracked successful-attempt allocation peak | 29,761 | 27,688-27,692 |
| Tracked rejected-attempt allocation peak | 29,457 | 27,635 |
| Stream object, already included above | 544 | 544 |
| Minimum observed main-task stack free / configured | 9,564 / 12,288 | 8,956 / 12,288 |
| Minimum observed TCP/IP-task stack free / configured | 2,132 / 3,584 | 2,164 / 3,584 |

All tracked allocations returned to zero after each destruction. TCP closing
records accumulated to four `TIME_WAIT` entries, then expired naturally. Global
internal heap free space rose from 335,900 to 336,768 bytes during RSA cooldown
and from 335,916 to 336,784 during ECDSA cooldown. Both cold baselines were
337,436 bytes; the remaining 668/652-byte cold-to-warm difference is not fully
attributed. Largest free blocks also remained below their cold values. These
observations do not prove complete heap recovery or long-run leak freedom.

Global heap includes the scoped TLS allocations, so do not add the two measures.
Its minimum-free figure is cumulative since boot, not an isolated TLS peak.
Snapshots are sequential, not globally atomic. Stack high-water marks use this
port's one-byte `StackType_t` and include the fixture and observation callbacks;
they are not minimum-safe stack sizes or hardware headroom guarantees.

The shared four-entry DNS pool occupies 1,152 linked bytes plus an 8-byte lock.
It is static storage, separate from dynamic heap observations. The embedded
test root occupies 1,156 RSA or 620 ECDSA bytes in read-only storage; its parsed
heap representation is already included in the tracked totals. The snapshot
semaphore is allocated before baseline and reused; this is measurement overhead.

An earlier broad allocator wrapper captured a four-byte allocation retained by
`pthread_setspecific` beyond an individual connection and failed the zero-live
assertion. The saved ELF attributes its caller to SDK thread-local list storage.
The final meter therefore labels only stream and Mbed TLS requests as TLS
allocations; global heap observations still include runtime costs. This narrows
attribution rather than claiming that all runtime storage has been freed.

This profile measures selected single-session paths. Wider concurrency, larger
or mixed certificate chains, allocation-failure recovery, interrupt stack use,
Wi-Fi, whole-firmware budgets and physical CPU/stack/heap behavior remain open.
No memory optimization or performance improvement is claimed by this increment.

### Repeated warm-baseline comparison

Add `--memory-rounds 3` alongside `--memory-accounting rsa` or
`--memory-accounting ecdsa` to repeat the eight attempts and natural cooldown
three times in the same boot. This variant requires 349 checks per profile and
takes approximately six minutes. The first post-cleanup snapshot establishes
the warmed reference; the next two allow comparison after the same work and
cleanup. No task, networking stack or emulator restart occurs between rounds.
The existing one-round command still requires 119 checks.

All rounds require zero tracked TLS allocations, zero active/TIME_WAIT TCP
records and no pending DNS at cleanup. Global free heap and largest-free-block
values are reported separately without imposing an arbitrary equality tolerance.
Passing these functional and cleanup checks alone does not mean that global
memory is stable: the post-cleanup measurements must also be examined. Three
rounds distinguish selected cold/warm behavior but do not replace a long soak or
attribute all retained runtime allocations.

In the initial three-round runs, post-cleanup free heap was exactly 336,744 bytes
after every RSA round and 336,760 after every P-256 round. Largest free blocks
were also unchanged across the three endpoints: 241,664 and 245,760 bytes,
respectively. Each profile completed 24 attempts; all scoped allocations returned
to zero after each attempt. There was no further heap loss across the two warmed
repeats in these runs. Cold-to-warm differences were 692/676 bytes and remain
not fully attributed. These are separate fixtures from the one-round measurements
above; compare endpoints within each run rather than treating small differences
between separate images as a retention trend. Stack watermarks were stable at
all three endpoints, without changing configured stack sizes.

## Selected allocation failures and recovery

Prepare with `--allocation-failures rsa` or `--allocation-failures ecdsa`.
Each separate profile requires 336 checks. It first warms the runtime through an
authenticated exchange and natural TCP cleanup, then repeats two cycles of:

- Rejecting the stream object's allocation before creating a handle.
- Rejecting the first scoped allocation during TLS setup, before TCP open.
- Rejecting the first scoped allocation after TCP connects, during the handshake.
- Rejecting the outgoing record buffer after the incoming buffer exists.
- Rejecting TLS state initialization after both record buffers exist.
- Rejecting the peer certificate's DER copy after its chain structure exists.

Every failure is followed by a fresh authenticated exchange. Each cycle ends
with natural TCP cleanup before taking its global heap comparison. Expect about
six minutes per run. A failed check, failed assertion or panic stops the
runner with the partial evidence preserved; a failed attempt is never reported
as a completed suite.

The test meter returns NULL exactly once on the selected task and records the
rejected request's byte count, successful allocations since arming, and live
bytes at arming and rejection. Later failures must retain earlier allocations
at the rejection boundary; counting earlier calls alone would not prove this.
It leaves other tasks and unwrapped allocation paths unchanged. Fault controls
add 28 linked metadata bytes to the original meter (4,153 total), excluding
alignment/code. The handshake fixture decorates its own
transport-open callback to arm rejection after successful TCP connect; the
production candidate and adapter are unchanged.

Creation must return NULL. Setup/handshake must report TLS_ERROR with the exact
allocation error and stage. Failed I/O must preserve caller output and the
diagnostic. Each destruction must release all scoped TLS bytes, and the next
connection must authenticate and exchange exact bytes without an injected fault.
The certificate-copy case requires `MBEDTLS_ERR_X509_ALLOC_FAILED`; the other
setup/handshake cases require `MBEDTLS_ERR_SSL_ALLOC_FAILED`.
The peer independently counts the recovery requests and handshake failure alerts.

Earlier three-point profiles passed 174 checks each; a separate uninstrumented
smoke run passed ten.
After warm-up and each of the two failure cycles, RSA free heap was exactly
336,736 bytes with a 241,664-byte largest block; P-256 was exactly 336,776 with
a 245,760-byte largest block. All scoped allocations returned to zero. These
runs rejected 544-byte stream, 16,717-byte setup and 408-byte handshake requests,
once per point per cycle. There was no observed additional global heap retention
after these selected failures and recoveries. This does not explain all initial
runtime storage or establish cleanup for untested allocation sites.

The expanded six-point profiles passed 336 checks each, plus ten uninstrumented
smoke checks. The added cases retained 16,717 bytes (incoming buffer), 21,146
bytes (both buffers) and 408 bytes (certificate structure) above their arming
baselines when the later allocation failed. Their rejected requests were 4,429,
220 and 840/444 bytes respectively; the last values match the actual RSA/P-256
peer certificate DER lengths. All scoped bytes returned to zero after destruction.

In these expanded runs, RSA free heap was 336,732 bytes after warm-up and 336,744
after each failure cycle. P-256 reported 336,740 at all three endpoints. Largest
blocks remained 241,664/245,760 bytes; main-task free-stack watermarks remained
9,076/8,580 bytes, with 2,140 free bytes on the TCP/IP task in both profiles.
No additional global heap retention was observed at the cleanup endpoints. The
12-byte RSA increase is not attributed or presented as an optimization. These
figures describe separate images from the earlier three-point runs.

This covers selected one-shot failures, not real heap exhaustion or every
allocation site. Root parsing, other setup/handshake allocations, DNS/socket/RTOS
failures, simultaneous sessions and long-run stability remain separate work.
Global heap observations overlap the scoped totals and require separate review;
zero tracked bytes does not prove complete cleanup of every runtime allocation.

## Certificate dates and abrupt closure

Prepare with `--security` for a separate 98-check RSA profile. It rejects
expired and future-dated leaves, EOF during handshake, TCP EOF without TLS
`close_notify`, and a peer reset after authentication. Every case requires the
exact diagnostic, immediate local socket release, stable terminal I/O behavior
and a fresh verified exchange. Only a complete authenticated prefix may be
returned before truncation; abrupt closure must never become successful EOF.

The existing host peer supplies the dated certificates and controlled closures.
OpenSSL independently verifies the actual IP identity, purpose and chain, then
the expected date error at the guest fixture UTC. The peer must observe the
specific expired/unknown certificate alerts and perform each requested closure.
Normal certificate verification stays enabled. Fixture UTC does not establish
trusted device time or clock freshness.

The profile uses a 3-second exchange budget with 250 ms scheduling allowance,
then up to 135 seconds for natural TCP cleanup. The runner allows 200 seconds
overall. Expected completion is roughly two minutes. It checks zero active and
closing TCP records and pending DNS, without allocation instrumentation or a
whole-heap claim. The initial run passed all 98 checks; authentication and smoke
regressions passed 83 and ten checks. This profile covers RSA only and does not
qualify arbitrary corrupted input, all completion races or physical hardware.

## Boundaries

The adapter has nonblocking lwIP socket operations with a bounded wait budget.
Cancellation is tested in selected DNS, connect, handshake, read and write cases.
Wider concurrency and complete target resource accounting remain separate validation.
The app uses IDF's own kernel and network configuration, not the host simulator's
headers. Its 12 KiB main-task allocation is a test setting, not a proven minimum
stack size. No total heap, leak-freedom, hardware timing or device headroom claim
follows from these tests.
