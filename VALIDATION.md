# Review checkpoint: 4 October 2026

This is the standalone FreeRTOS/lwIP/Mbed TLS client project requested during
[the HTTPS review](https://github.com/GideonZ/1541ultimate/pull/936#issuecomment-5876427638).
It uses Mbed TLS for cryptography. The host reference port has no Ultimate
firmware or ESP32 communication dependency. The optional ESP-IDF emulator port
is a separate validation layer.

The tested source is `529b0450955611bd82db921db3bae10222203eba`. The publication
commit adds this index and its README link only; it does not change that source,
the dependencies, or the tests. The source archives in the evidence package
retain the exact tested revisions.

## Results and evidence

[Download the source and evidence checkpoint](https://github.com/araxis/ultimate-tls-validation/releases/tag/review-20261004).
The release includes file manifests, raw client logs, independent peer records,
result JSON, acceptance limits and replayed audits. Failed or deliberately stopped
runs remain distinguished from passing runs. Absolute paths in raw records
describe the original environment and are not installation requirements.

| Source | Validation | Result |
| --- | --- | --- |
| `2327e1f2` | Full host regression, normal and UBSan builds | 2,536 checks across 28 runs |
| `2327e1f2` | ESP32-S3 emulator regression | 2,049 checks across 12 profiles |
| `529b0450` | Focused duration-fixture validation | 597 positive checks; six acceptance unit tests; 13 damaged-evidence variants rejected |
| `529b0450` | RSA same-boot emulator duration profile | 60 rounds, 480 attempts, 6,904 checks; host and guest duration over two hours |
| `529b0450` | ECDSA same-boot emulator duration profile | 60 rounds, 480 attempts, 6,904 checks; host and guest duration over two hours |
| `529b0450` | Fresh source export and host build | 32 RSA plus 54 ECDSA checks |

The seven changed files between the two revisions concern duration fixtures;
the TLS core, transport and resolver are unchanged. Do not combine these rows
into a claim that a single full regression was run on the later revision.
The intentional operator-stop run is incomplete and excluded from pass totals.
The proposed eight-hour tier was deferred and has not been run.

After each duration-profile attempt, scoped allocation ownership returned to
zero. Sampled warmed heap and largest free blocks remained stable within the
acceptance limits fixed before execution. These scoped counters exclude some
allocation paths and overhead; they are not whole-device memory budgets or proof
of leak freedom. Stack watermarks likewise describe the instrumented emulator
fixture, not the eventual product call chain.

## Reproduction

Follow [the host setup and test commands](README.md#reproduce-on-linux-or-wsl)
and [the optional emulator instructions](ports/esp_idf/README.md).
Dependencies are pinned in [dependencies.json](dependencies.json).
Run the TAP-based tests sequentially; do not share the interface between runs.
The wrapper removes its temporary interface when it finishes. No physical board
or public service is the test endpoint.

The release also contains a separate HTTP evidence archive for the small fixes
extracted from #936. Those HTTP fixes are not part of this repository's TLS code.
Its original local-draft notes describe the point at which that evidence was
collected; current submission status is linked from
[the original draft](https://github.com/GideonZ/1541ultimate/pull/936).

## What remains unfinished

This is an experimental client-side validation checkpoint, not an HTTPS firmware
release or an integration-ready library. It does not implement a TLS server.
The current API covers bounded exchanges with a single task owner; it does not
promise concurrent handle use or a long-lived messaging connection.

Firmware integration still needs an agreed execution boundary and product scope,
narrow transport/session adapters, physical entropy and trusted-time provisioning,
trust-root policy, restart and queue-ownership tests, and whole-device memory,
stack and timing measurements. The host FreeRTOS version and emulator SDK differ
from parts of the product firmware. Physical device, UART, update and Wi-Fi
qualification remains separate. Parser/client compatibility changes also remain
outside this checkpoint.

The C64-facing goal remains authenticated HTTPS through the existing target-6
HTTP request/response interface. Emulator passes and older prototype hardware
results do not establish that the revised integration is ready to merge.
