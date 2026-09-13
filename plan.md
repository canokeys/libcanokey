# Implementation plan

[README](README.md) lists available features; [API contracts](docs/api-design.md)
define ownership and execution. This plan contains only remaining work in this
repository. Consumer integration and upstream changes require a separate task.

## Complete PIV

1. ML-DSA message/context signing and randomized Ed25519 streaming, including empty
   messages. Confirm mode selection, framing, response streaming and bounds against
   pinned firmware; never substitute classic Ed25519 or prehash semantics implicitly.
2. SM2 full-message signing and its distinct key-agreement protocol. Specify IDs,
   ephemeral state, result encoding, cancellation and application key confirmation.
3. Metadata directory and per-slot container names; retain certificate-only entries,
   unknown fields and malformed-entry diagnostics where the protocol permits them.
4. Key move/delete, retry configuration and algorithm-configuration writes. Confirm
   version/slot support, authentication, cache invalidation and partial-write effects.

Extend Batch and the experimental C ABI alongside core operations. Acceptance:
transcripts for SELECT/authentication/target ordering, chaining/continuation,
malformed responses, failure/cancellation and budgets; owned typed results and size
queries that never execute operations. Unsupported evidence must fail at construction;
do not add factories that always return Unsupported.

## Other applets

| Milestone | Scope and acceptance focus |
| --- | --- |
| Full Admin | Device/config/storage/chip/core-commit reads, configuration updates, PIN, NFC/NDEF, SM2 configuration and explicit applet reset; preserve unknown bits and report profile invalidation/partial writes |
| OATH | Access validation, credentials and calculations with caller-supplied challenge/time/randomness; implement 06/A5 and nonempty-9000 continuation; never retry HOTP side effects |
| OpenPGP | DOs, PW1-sign/PW1-other/PW3, KDF, keys/policies and private operations with independent firmware evidence; caller-supplied fingerprints/timestamps |

FIDO/CTAP, Python bindings and consumer adoption are separate scope decisions.
Integration should start with PKCS#11, then Console/ckman, and needs controlled
hardware/usbip checks across supported firmware. It is not a prerequisite for
continuing this library. Consumers must share one connection lock and disable
transport continuation/retries before adopting operations.

## Delivery

Follow [AGENTS.md](AGENTS.md) for tests, native/wasm dependency checks, examples,
rustdoc, C/C++ ABI checks and staged Conventional Commits. Retain existing features.
Offline transcripts establish encoding behavior, not hardware interoperability.
Freeze the C ABI only after implementation and consumer validation are complete.
