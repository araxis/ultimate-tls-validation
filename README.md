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
uses DNS port 1053 and TLS ports 8443/8444, bound only to `.1`. Do not run multiple
probes concurrently on this interface. Certificates and private test keys are
created per run under ignored `evidence/`; they are never installation roots.

For undefined-behavior instrumentation of the executable and its dependencies:

```sh
cmake -S . -B build/ubsan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DTLS_LAB_UBSAN=ON
cmake --build build/ubsan -j 4
sudo python3 tools/run_local.py --uid "$(id -u)" --binary build/ubsan/tls_probe
```

Each run writes `probe.log`, `peer-events.json` and `result.json` to a fresh
evidence directory. Failure, timeout or incomplete accounting returns nonzero.
Eight cases produce 32 checks: valid trust, hostname rejection, recovery,
unknown-root rejection, recovery, unavailable time, unavailable entropy, final
recovery. Successful cases compare exact response bytes and require TLS
close-notify. TLS 1.2 is restricted to ECDHE with AES-128-GCM and RSA/ECDSA
authentication. No plaintext fallback or certificate-verification bypass exists.

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

Known remaining work: DNS cancellation and precise whole-operation deadlines
during DNS resolution (the current lwIP DNS retries are bounded but not cancelled
by a shorter stream deadline); cancellation at other phases; expired/future
certificates; peer stalls; transport truncation; allocation failures; bounded
socket/heap/queue accounting; concurrency; performance budgets; a second port.
The current destroy operation aborts TCP after releasing the stream and does not
perform a potentially blocking bidirectional TLS shutdown.

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
