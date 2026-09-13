# Implementation plan

Current APIs and examples are listed in [README](README.md); contracts live in
[API design](docs/api-design.md). This plan tracks remaining work. Consumer
integration and upstream changes require a separate task.

## Next: complete PIV

1. Verify management-key modes and firmware coverage against CanoKey evidence.
   Implement explicit external/mutual authentication with maintained block-cipher
   and constant-time comparison dependencies; randomness remains caller-supplied.
2. Add authenticated object/certificate writes and management-key updates.
3. Add metadata, key generation/import, signing, decryption, and derivation.
4. Implement Batch for explicit authentication and dependent operations under one
   SELECT. Preserve completed-item counts on failure without rollback or replay.

Extend the experimental C ABI alongside useful core operations. Before enabling
metadata directories, key move/delete, retry/configuration writes, or ML algorithms,
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

## External certificate dependency

Switch the sibling path dependency to the x509-info crates.io version when ready and remove its extra CI checkout. Certificate-library development
and release tracking belong to the independent repository.

## Delivery

Follow [AGENTS.md](AGENTS.md) for implementation checks and staged Conventional
Commits. Keep native/wasm dependency boundaries, runnable examples, public rustdoc,
and C/C++ ABI checks in CI. Freeze the C ABI only after its complete implementation
and integration are validated.
