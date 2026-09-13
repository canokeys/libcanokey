# Implementation plan

Current APIs and examples are listed in [README](README.md); contracts live in
[API design](docs/api-design.md). This plan tracks remaining work. Consumer
integration and upstream changes require a separate task.

## Next: complete PIV

Remaining algorithm extensions: additional curve scalar import/derivation and
ML/empty-Ed25519 streaming private operations, with explicit firmware evidence.

Extend the experimental C ABI alongside useful core operations. Before enabling
metadata directories, key move/delete, retry/configuration writes, or ML private-operation modes,
resolve the [evidence gaps](docs/api-design.md#later-protocols-and-evidence-gaps).

Acceptance: transcript coverage for SELECT/authentication/target ordering,
continuation/chaining, failure/cancellation, bounds, and secret cleanup; typed C
results and size queries that never execute operations. Do not introduce factories
that always return Unsupported.

## Subsequent milestones

| Work | Acceptance focus |
| --- | --- |
| PKCS#11 adoption, then Console and ckman | Application-owned connections/state; raw transport; one device lease across each operation; complete relevant bindings |
| Full Admin | Configuration/storage reads and writes, PIN, NFC/NDEF and explicit reset; profile invalidation and partial-write semantics |
| OATH | Credentials/access/calculations, applet-specific continuation, touch and HOTP side effects |
| OpenPGP | DOs, PIN/KDF, keys and private operations with independent firmware/algorithm evidence |
| Additional PIV/FIDO scope | Enable by demonstrated capability; retain existing CTAP backends until separately evaluated |

Integration requires controlled hardware/usbip checks across supported firmware;
offline tests alone do not establish interoperability. Existing and new consumer
paths must share one connection lock and disable duplicated continuation/retries.

## Delivery

Follow [AGENTS.md](AGENTS.md) for implementation checks and staged Conventional
Commits. Keep native/wasm dependency boundaries, runnable examples, public rustdoc,
and C/C++ ABI checks in CI. Freeze the C ABI only after its complete implementation
and integration are validated.
