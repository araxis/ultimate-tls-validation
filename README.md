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
The completion-boundary suite uses ports 8473 through 8484.

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
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe --boundaries
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

The `--boundaries` suite has 155 checks across 12 controlled completion orderings.
It expires the stream after TCP open, before/after an application write, after a
buffered read, after verified handshake completion and after decoding authenticated
close_notify. Cancellation from a synchronized FreeRTOS task exercises the last
three completion points; a simultaneous buffered-read case verifies cancellation
precedence. Other cases verify that a 3,000 ms total budget forwards only 2,000 ms
to write and 1,000 ms to read as time advances, and that already-returned authenticated
EOF remains terminal after later expiry/cancellation.

The fixture controls only the stream's monotonic clock; certificate UTC and lwIP
transport timers remain real. Wire framing identifies the final encrypted handshake
record and close alert without decrypting or changing bytes. The trigger skips the
transport callback's completion check and fires at the following TLS completion
check; successful decode diagnostics are required. Buffered cases first consume
one byte of an authenticated record, then verify that the next read performs no
transport receive. The fixtures prove these selected orderings, not every scheduler
interleaving or hard real-time timing. Normal host-clock wait tests remain separate.

These tests reproduced a buffered-read bug: TLS had already copied authenticated
plaintext into the caller buffer when the final deadline/cancellation check rejected
the operation. Reads now stage at most 512 bytes on the stack and copy to the caller
only after that check succeeds. Failed and EOF reads leave the caller buffer unchanged.
This adds a bounded stack buffer and a copy per successful read; embedded stack and
performance costs still require qualification. No heap allocation or public handle
layout change is introduced. A failed write may already have reached the peer, so
failure does not authorize automatic retry. All failed handles remain unusable;
authenticated EOF still requires destruction to release the socket.

## Host memory and direct stack frames

Compile a before/after comparison without changing the runtime build:

```sh
python3 tools/measure_stack.py --build build --baseline 3a7982d51f9ff16f25342810a91c692c047d10e4
```

The tool reads the actual Ninja compiler command, preserves its include paths and
configuration, and adds GCC `-fstack-usage` for isolated source copies. It also
compiles `-O2` and `-Os` comparisons; these two profiles are compile-only measurements,
not runtime-qualified builds. Each fresh `evidence/stack-*` directory preserves
commands, compiler identity/target, source hashes, objects, frame reports, layout
symbols and disassembly. A successful result means the measurement completed and
object layouts stayed equal, not that a firmware memory budget passed.

GCC 15.2.0 on x86-64 reported these direct `tls_stream_read` frame sizes for the
read-output staging fix:

| Compilation | Before | After | Increase |
| --- | ---: | ---: | ---: |
| Existing debug flags | 64 bytes | 592 bytes | 528 bytes |
| `-O2` | 48 bytes | 576 bytes | 528 bytes |
| `-Os` | 48 bytes | 576 bytes | 528 bytes |

These are individual compiler-reported frames, excluding callers, callees, TLS
crypto, transport code, interrupts and signals. They are not peak task stacks or
safe task-stack settings. The increase exceeds the 512-byte payload buffer because
the generated frame also changes; other architectures/compilers may differ.

The opaque stream object remains 1,416 bytes in this host ABI. Its embedded SSL
context (568 bytes), configuration (392 bytes) and DRBG (344 bytes) are already
included in that total and must not be added again. A trust-store root node is
744 bytes before separately allocated certificate/key data. These sizes are not
portable firmware constants. The tracked handshake runs measured 41,486 bytes
retained after successful open and a 48,586-byte requested-allocation peak; all
tracked allocations returned to zero after destruction. Those figures include
stream/trust/TLS allocations within the existing per-task calloc scope, exclude
allocator overhead and other tasks, and do not establish whole-process leak freedom.

The POSIX port reserves a FreeRTOS task stack but calls `pthread_attr_setstacksize`
and `pthread_create` without assigning that buffer as the pthread stack. Execution
therefore uses a separate host stack. A FreeRTOS watermark of the reserved buffer
would not measure TLS execution. The probe's 32,768 StackType_t depth corresponds
to a 262,144-byte reservation with this 8-byte host type; the lwIP port interprets
its 32,768 stack setting as bytes instead. Neither is a device budget. The configured
2 MiB FreeRTOS heap and 128 KiB lwIP heap are also separate from host TLS calloc.

Before integration, collect frames and call-chain/stack observations with the exact
target compiler, firmware configuration and FreeRTOS port; include cryptographic
peaks, interrupt overhead, concurrent sessions, retained TCP state and safety margin.
Account TLS allocations, RTOS objects/stacks and network buffers without double
counting. The read copy's execution cost, whole-process retention, and target stack
headroom remain unqualified. Keep the verified failure semantics while evaluating
those budgets; host measurements alone do not justify shrinking task stacks.

Socket waits poll the atomic cancellation flag in slices of at most 10 ms. DNS
submission to the TCP/IP task is nonblocking. Already submitted DNS queries can
continue after the caller has returned; the fixed `DNS_TABLE_SIZE` slot pool
bounds that retention until a reply or lwIP timeout. If all slots are retained,
a new lookup fails without allocating more memory. This is caller cancellation,
not cancellation of packets already sent by lwIP. The cancellation source must
finish before its transport context is destroyed.

## ESP32-S3 compiler comparison

`tools/measure_target.py` accepts a saved ESP-IDF compilation database and SDK:

```sh
python3 tools/measure_target.py \
  --compile-commands /path/to/controller/build/compile_commands.json \
  --sdk /path/to/esp-idf \
  --baseline 3a7982d51f9ff16f25342810a91c692c047d10e4
```

It replaces the original TLS source/include with isolated standalone copies,
retains the command's target flags and generated `mbedtls/esp_config.h`
configuration, and compiles before/after objects with `-fstack-usage`. It does
not invoke the firmware build, link, run target code or install an image. Each
`evidence/target-*` directory records the original command, compiler identity,
configuration snapshots, consumed-header hashes, source hashes, objects,
disassembly, layout symbols and direct frame reports. The tool rejects a compile
that uses another public TLS header or misses the expected SDK configuration.

The saved controller configurations produced these compile-only results, with
their existing `-Og` flags:

| SDK / Mbed TLS | ESP32-S3 GCC build | Read frame before | Read frame after | Stream object |
| --- | --- | ---: | ---: | ---: |
| ESP-IDF 5.3.1 / 3.6.0 | 13.2.0, 20240530 | 32 bytes | 544 bytes | 544 bytes |
| ESP-IDF 5.3.6 / 3.6.7 | 13.2.0, 20250707 | 32 bytes | 544 bytes | 544 bytes |

Both target compilers report a 512-byte increase for read staging, compared with
528 bytes on the measured x86-64 host. The 544-byte target stream object is
unchanged by the fix; it includes the SSL context (252 bytes), configuration
(140 bytes) and DRBG (76 bytes). The separate root-node structure is 408 bytes;
certificate/key data and other dynamic allocations are additional. Neither the
object size nor the direct read frame measures a session's total memory.

These SDK configurations enable hardware AES/MPI/SHA, internal-memory TLS
allocation, 16,384-byte incoming and 4,096-byte outgoing record buffers, retained
peer certificates and fixed buffer lengths. The host allocation figures above
cannot be used as target heap budgets. SDK 5.3.1 was installed from an archive:
its version headers and consumed inputs are captured, but its saved command's
`IDF_VER` is `HEAD-HASH-NOTFOUND` and no SDK Git revision is claimed. SDK 5.3.6
has a recorded Git revision in the measurement evidence.

Both SDKs contain ESP-IDF's FreeRTOS 10.5.1 kernel and an Xtensa `StackType_t` of
`uint8_t`. This differs from the management processor's FreeRTOS 10.2.0 and the
lab's POSIX FreeRTOS 11.1.0. The existing controller's 12,288-byte TLS-worker
setting is context, not a validated budget for this candidate. The isolated
wrapper does not exercise a FreeRTOS task or the firmware adapter, and these
measurements do not qualify another runtime port, hardware entropy, complete
call-chain stack use, target heap retention or the read copy's execution cost.

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
