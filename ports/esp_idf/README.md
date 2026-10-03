# ESP32-S3 emulator probe

A separate ESP-IDF application compiles the same `src/tls_stream.c` and public
header as the host reference. Its small test adapter accepts IPv4 literals only.
This first slice exercises one verified RSA exchange, exact request/response
bytes, authenticated EOF, socket cleanup and advancing FreeRTOS ticks. It does
not qualify DNS, cancellation, wider concurrency, Wi-Fi or physical hardware.

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

## Boundaries

The adapter has nonblocking lwIP socket operations with a bounded wait budget.
Cancellation is exposed through its context but is not exercised by this first
probe. DNS ownership and target-specific locking must be validated separately.
The app uses IDF's own kernel and network configuration, not the host simulator's
headers. Its 12 KiB main-task allocation is a test setting, not a proven minimum
stack size. No total heap, leak-freedom, hardware timing or device headroom claim
follows from this smoke test.
