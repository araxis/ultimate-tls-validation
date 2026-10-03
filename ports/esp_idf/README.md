# ESP32-S3 emulator probe

A separate ESP-IDF application compiles the same `src/tls_stream.c` and public
header as the host reference. Its small test adapter accepts IPv4 literals only.
The default smoke test exercises one verified RSA exchange, exact request/response
bytes, authenticated EOF, socket cleanup and advancing FreeRTOS ticks. Optional
RSA and P-256 ECDSA profiles test authentication rejection and recovery. These
tests do not qualify DNS, wider concurrency, Wi-Fi or physical hardware. A separate
timing profile covers selected handshake/read deadlines and cancellation.

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

## Boundaries

The adapter has nonblocking lwIP socket operations with a bounded wait budget.
Cancellation is tested in the selected handshake/read cases only. DNS ownership
and target-specific locking must be validated separately.
The app uses IDF's own kernel and network configuration, not the host simulator's
headers. Its 12 KiB main-task allocation is a test setting, not a proven minimum
stack size. No total heap, leak-freedom, hardware timing or device headroom claim
follows from these tests.
