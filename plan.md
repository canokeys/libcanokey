# Implementation plan

[README](README.md) lists available features; [API contracts](docs/api-design.md)
define ownership and execution. This plan contains only remaining work in this
repository. Consumer integration and upstream changes require a separate task.

## Complete PIV

1. ML-DSA nonempty-context and prehash signing: pinned firmware hardcodes empty
   context and exposes no such modes. Requires new firmware evidence before enablement.
2. Interactive peer exchange between SM2 initiator steps and PIN-always initiators
   need further protocol/API evidence. Current operations require peer keys upfront;
   pinned firmware clears agreement state on VERIFY and consumes PIN-always at step 1.

Extend Batch and the experimental C ABI alongside core operations. Acceptance:
transcripts for SELECT/authentication/target ordering, chaining/continuation,
malformed responses, failure/cancellation and budgets; owned typed results and size
queries that never execute operations. Unsupported evidence must fail at construction;
do not add factories that always return Unsupported.

## Other applets

| Milestone | Scope and acceptance focus |
| --- | --- |
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
