# Standalone TLS validation

A local feasibility project for authenticated byte streams over FreeRTOS and
lwIP. The request driver sends a small HTTP request to a controlled TLS peer.
It does not depend on an Ultimate checkout, ESP32 communication, UCI, device
menus or firmware diagnostics. This is validation work, not a firmware release.

## Structure and ownership

- `src/tls_stream.c` owns each connection's TLS configuration, session and DRBG.
  Its opaque handle has one task owner and one total exchange deadline. The
  platform supplies transport, entropy, trust and clock qualification callbacks.
- `platform/lwip_transport.c` owns the lwIP socket and loaded trust anchors.
  The stream is destroyed before its callback context. The adapter explicitly
  calls `lwip_*` functions; it does not use the operating system's TCP sockets.
- `platform/lwip_dns.c` bounds DNS waits and owns pending callback storage. Each
  slot has a waiting-task reference and a core-callback reference. Cancellation
  releases the task's reference immediately; the slot cannot be reused until the
  callback has also completed. Caller buffers are never retained by the callback.
- `platform/tap_network.c` connects Ethernet frames to a private Linux TAP
  interface. Its receive task is scheduled by FreeRTOS. lwIP's unchanged
  FreeRTOS `sys_arch` port supplies queues, semaphores, tasks and timers.
- `tests/run_probe.py` supplies separate DNS and TLS peers, records SNI and
  request bytes, and checks complete case accounting independently of the probe.

The narrow portable interface carries bytes, not HTTP-specific request types.
Its public interface is experimental until cancellation, concurrency and fault
testing establish the final contract.

## Reproduce on Linux or WSL

Required tools: C compiler, CMake 3.20+, Ninja, Git, Python 3.11+, OpenSSL CLI,
iproute2, pthreads and `/dev/net/tun`. Python uses the standard library only.

```sh
python3 tools/bootstrap.py
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j 4
sudo python3 tools/run_local.py --uid "$(id -u)"
```

On Windows, run those commands in WSL. If sudo is unavailable, invoke the wrapper
through `wsl -d Ubuntu -u root -- python3 <Linux path to tools/run_local.py> --uid 1000`
(substitute your normal Linux user ID). The wrapper uses `runuser` to start the
test process and peers as that user, then removes the TAP interface in `finally`.
The interface is temporary and must be recreated after WSL restarts.
Setup refuses to replace an
existing interface or overlap an existing non-default route. No forwarding,
NAT, firewall changes, internet test endpoint or physical device is required.

The private subnet is `192.0.2.0/30`: Linux is `.1`, lwIP is `.2`. The fixture
uses DNS port 1053 and TLS ports 8443 through 8447, bound only to `.1`. Do not run multiple
probes concurrently on this interface. Certificates and private test keys are
created per run under ignored `evidence/`; they are never installation roots.
The connection-fault suite also reserves TCP ports 8448 and 8449 without listening.
The session suite uses binary TLS peers on ports 8450 through 8455.
The certificate/closure suite uses ports 8456 through 8463.
The handshake allocation suite uses a dedicated TLS peer on port 8464.
The malformed-record suite uses ports 8465 through 8472.

For undefined-behavior instrumentation of the executable and its dependencies:

```sh
cmake -S . -B build/ubsan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DTLS_LAB_UBSAN=ON
cmake --build build/ubsan -j 4
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe --faults
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe --pressure
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe --connections
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe --sessions
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe --security
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe --allocations
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe --handshake-allocations
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe --records
```

Each run writes `probe.log`, `peer-events.json`, `source-manifest.json` and
`result.json` to a fresh evidence directory. The manifest hashes the local source,
configuration and harness files before execution; the result includes the binary
hash and dependency pins. Failure, timeout or incomplete accounting returns nonzero.
Eight cases produce 32 checks: valid trust, hostname rejection, recovery,
unknown-root rejection, recovery, unavailable time, unavailable entropy, final
recovery. Successful cases compare exact response bytes and require TLS
close-notify. TLS 1.2 is restricted to ECDHE with AES-128-GCM and RSA/ECDSA
authentication. No plaintext fallback or certificate-verification bypass exists.

The separate `--faults` suite has 40 checks: silent DNS timeout, cancellation
from another FreeRTOS task, a DNS reply arriving after caller destruction,
eventual release of all lookup slots, stalled-handshake timeout/cancellation,
stalled-read timeout/cancellation and a verified recovery request. It checks the
actual failure phase and independent peer events as well as status and elapsed
time. Timing assertions allow 250 ms of host scheduling tolerance; that is not
an extension of the requested deadline or a hard real-time guarantee.

The separate `--pressure` suite has 61 checks with the pinned configuration:

- Four abandoned DNS lookups fill the slot pool. A fifth fails promptly; the
  original slots remain owned until their callbacks complete, then all retire.
- A bounded test callback holds the TCP/IP task while 32 entries fill its actual
  mailbox. Another DNS submission fails promptly and releases its message and
  lookup slot. A second case expires a queued lookup before the core can run it;
  the independent DNS peer verifies that this abandoned query is never sent.
- A verified TLS peer stops reading after sending a readiness byte. A second
  FreeRTOS task observes a non-writable lwIP socket before issuing cancellation.
  Timeout and cancellation are checked independently, with socket, netconn and
  TCP PCB release, followed by a verified recovery exchange. The peer separately
  records unread ciphertext and connection closure.

These are bounded functional checks on the reference port. Callback-message,
netconn and TCP PCB pool restoration does not establish whole-process or TLS
heap leak freedom. The core gate and write observer live only in the test driver.

The `--connections` suite has 42 checks: a real TCP refusal, a connection timeout,
cancellation after an emitted SYN, and a verified recovery exchange. The peer
reserves two ports without listening, so any SYN reaching either port is refused.
The test driver temporarily wraps the lwIP interface's output to discard SYNs
for only the stalled port. A semaphore reports the emitted SYN before another
task requests cancellation. This exercises the actual nonblocking TCP connect
path without changing host firewall rules or adding transport hooks. The wrapper
is installed and restored on the TCP/IP task, with a completion barrier before
releasing its semaphore. Each failure checks immediate socket release, safe
destruction and restoration of netconn, TCP PCB and TCP segment pools. These
short cases do not cover TCP retransmission exhaustion or network recovery races.

The `--sessions` suite has 63 checks. Test adapters limit actual transport reads
to 13 bytes and writes to 17 bytes, while callers exchange a 1025-byte binary
payload in larger operations. Independent peers and clients compare exact bytes.
Cancellation is exercised before open and at deterministic completion boundaries:
another task cancels after a successful TCP open, read or write callback, before
that callback returns to the TLS layer. Two verified sessions are then held open
simultaneously; one is cancelled while the other completes its own distinct
payload and authenticated closure. This proves the selected orderings and session
isolation, not exhaustive race coverage or concurrent access to a single handle.

Socket release does not imply immediate TCP PCB reclamation. The pinned lwIP
implementation can close normally with zero linger when no outgoing data is
pending. The session suite allows up to one second for local FIN processing,
requires no remaining active connections or queued segments, and permits at most
two TIME_WAIT PCBs belonging only to the successful binary sessions. With no live
connections, it explicitly advances the TCP slow timer through two maximum segment
lifetimes and verifies reclamation. This is a test of timer logic; it is not a
wall-clock retention measurement, long soak or total heap leak check.

The `--security` suite has 71 checks. Two leaves use the trusted issuer, correct
hostname and server-auth extensions but have expired or future validity dates.
OpenSSL independently verifies their chain, hostname and purpose with date checks
disabled, then confirms the expected date rejection with normal verification.
The client itself always checks dates and must return exactly the corresponding
Mbed TLS certificate flag. Per-run `date-fixtures.json` records actual dates,
verification output and certificate hashes; the host clock is not modified.

Three closure peers test EOF after a complete ClientHello, TCP FIN after a complete
authenticated application record without TLS close_notify, and TCP reset after a
verified handshake and client marker. The first must fail during handshake; the
second returns only the authenticated prefix followed by TLS_TRUNCATED; the third
returns TLS_TRANSPORT_ERROR. Each checks prompt failure, socket release and safe
destruction, followed by a verified recovery exchange.

Three additional peers use OpenSSL memory BIOs to construct real TLS 1.2
AES-GCM application records after a verified handshake and client marker. They
send only 3, 17 or 45 bytes of a 46-byte record, cutting the header, encrypted body
or authentication tag respectively, then send TCP FIN without close_notify.
Independent peer logs check the record and cut sizes. Each case must return
TLS_TRUNCATED with zero application plaintext and release its socket. This tests
selected cuts, not every offset or arbitrary malformed records.

The `--allocations` suite sweeps each calloc attempt on the constructor, trust-file
loading and TLS setup path before networking. GNU link wrappers inject a single
failure at a time in the calling POSIX task only and track its allocations until
destruction. They are disabled in other tasks and suites. The underlying allocator
and dependency sources are unchanged. A test callback deliberately rejects TCP
open so the baseline reaches the same pre-network boundary on every run.

The pinned build currently has 15 allocation points and 76 checks, including a
second uninjected setup and a real verified HTTPS recovery. Every injected failure
must be reached, reject construction/setup, leave no socket and free all tracked
allocations. This is not global heap instrumentation: malloc/realloc, shared-library
internals, handshake-time allocations, lwIP pools and FreeRTOS heap exhaustion are
outside this sweep. The reported peak is requested calloc payload on this host,
not allocator overhead or an embedded RAM requirement.

The separate `--handshake-allocations` suite opens real TCP connections before
arming injection. Its first verified handshake measures the observed allocation
call count. It then fails the first 16 calls, the last 8, and 16 evenly spaced
later calls, deduplicated into at most 39 injected attempts. These are sampled
call ordinals, not exhaustive source allocation sites. A selected call that is
not reached fails the test; the suite does not silently skip it or assume that
randomized handshakes always have identical allocation paths.

Each injected attempt must fail during TLS handshake, close its socket promptly,
and free every tracked allocation after stream and trust-store destruction.
Logs distinguish allocations retained at open return from those retained after
destruction, and report the requested-byte peak. The dedicated peer accounts for
every TCP connection independently, including expected handshake aborts. The
uninjected attempts before and after the sample must exchange exact binary
markers and receive authenticated close_notify; a normal HTTPS recovery follows.
The observed 6,231-call handshake gives 39 selected failures and 294 checks.
This extends per-task calloc/free coverage into the handshake; it does not cover
all allocation calls, malloc/realloc, other tasks, full heap usage or firmware
memory limits. No TLS implementation or dependency allocation policy is changed.

The `--records` suite has 103 checks across eight selected post-handshake faults:
unknown record type, invalid version, zero ciphertext length, oversized advertised
length, single-bit corruption of the explicit nonce, ciphertext and authentication
tag, and replay of an already accepted encrypted record. OpenSSL memory BIOs build
the original TLS 1.2 AES-GCM records after a verified handshake and client marker.
Peer evidence retains both original and transmitted ciphertext; a separate checker
verifies the exact header changes, bit offsets and duplicated bytes. The peers keep
TCP open until the client closes, so rejection cannot rely on a preceding peer EOF.

Each case requires TLS_ERROR during read, its exact dependency diagnostic, prompt
socket release, an untouched caller buffer on failed reads and refusal of later
reads/writes without overwriting the original diagnostic. The replay case returns
the authenticated original payload exactly once; the other cases return no
application bytes. A verified HTTPS exchange confirms subsequent recovery.
The oversized header returns MBEDTLS_ERR_SSL_BAD_INPUT_DATA from the pinned
dependency's input-buffer bound; the other malformed headers return
MBEDTLS_ERR_SSL_INVALID_RECORD, and the four authentication failures return
MBEDTLS_ERR_SSL_INVALID_MAC. Zero ciphertext length here is a malformed wire
record, not a valid encrypted record carrying an empty application payload.
These deterministic examples do not replace fuzzing, handshake-message validation,
all length boundaries, other cipher suites or whole-process memory accounting.

Socket waits poll the atomic cancellation flag in slices of at most 10 ms. DNS
submission to the TCP/IP task is nonblocking. Already submitted DNS queries can
continue after the caller has returned; the fixed `DNS_TABLE_SIZE` slot pool
bounds that retention until a reply or lwIP timeout. If all slots are retained,
a new lookup fails without allocating more memory. This is caller cancellation,
not cancellation of packets already sent by lwIP. The cancellation source must
finish before its transport context is destroyed.

## Dependency baseline and limits

`dependencies.json` pins full commits; bootstrap never patches dependencies.
lwIP uses Ultimate upstream's `26a2215` pin (reports 2.2.1d). Mbed TLS uses the
`2b96dd8` revision from the existing HTTPS workflow's ESP-IDF 5.3.6 matrix
(reports 3.6.7). This reference build uses that dependency's host configuration,
not ESP-IDF's generated hardware configuration. FreeRTOS uses the official
11.1.0 POSIX simulator; Ultimate currently vendors 10.2.0. That version and port
difference is an explicit unqualified integration boundary.

This first experiment proves scheduled lwIP traffic and authenticated exchanges
on the Linux reference port. It does not qualify firmware, hardware entropy,
embedded RAM/stack limits, throughput, long-run stability or another RTOS port.
POSIX simulation uses pthreads and larger host stacks; those sizes cannot be
reported as embedded memory measurements. Undefined-behavior instrumentation
does not imply address/leak sanitizer coverage.

The reference entropy source is Linux `getrandom`. Certificate dates use the
host's configured UTC clock; its synchronization must be established by the
operator. The missing-time test exercises the explicit clock-unavailable path,
not a simulated expired certificate. TLS 1.3 and custom end-user root provisioning
are outside this first exercise.

Known remaining work: broader cancellation/close-notify and deadline races;
exhaustive handshake and transport/kernel allocation failures; broader malformed-input coverage;
full socket/heap/queue accounting; broader concurrency; performance budgets; a second port.
The current destroy operation releases the socket with zero linger and does not
perform a potentially blocking bidirectional TLS shutdown. TCP closing/TIME_WAIT
state may outlive that socket; platform resource budgets must include it.

## Source provenance

The stream began with `software/network/https/tls_stream.c` at
`araxis/1541ultimate` revision `fc1498932ac0c01b16786660262ce2181fa3c80e`.
This extraction removes HTTP validation/types, makes entropy a platform contract,
and sets an explicit cipher policy. `LICENSE.txt` is preserved from that source.
Third-party dependencies retain their own licenses and notices in `.deps`.
The standalone source is the candidate to validate before any later integration;
no firmware copy has been updated as part of this work.

Port references: [FreeRTOS Linux simulator](https://www.freertos.org/Documentation/02-Kernel/03-Supported-devices/04-Demos/03-Emulation-and-simulation/Linux/FreeRTOS-simulator-for-Linux)
and [lwIP OS abstraction](https://www.nongnu.org/lwip/2_1_x/group__sys__os.html).
