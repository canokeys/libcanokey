# Documentation map

This directory separates **design documents** (normative contracts and the
evidence behind them, owned by this repository) from **user documents**
(guidance for consumers integrating the library).

## Architecture overview

libcanokey is a caller-owned, transport-free host protocol library for CanoKey
devices. The core contains no I/O, transport trait, async runtime, enumeration,
threads, or mutable globals. Callers own the `DeviceProfile` and every
`Operation<T>`; operations are state machines driven by `start`/`advance`, and
command/result getters never advance or resend. Layering:

- `canokey-protocol` — APDU/TLV codecs, the operation engine (continuation,
  chaining, budgets), typed errors and redacted secret buffers.
- `canokey-compat` — evidence-based firmware rules: capabilities per version
  range, observed algorithm configuration, Unknown vs Unsupported.
- Applet crates (`canokey-piv`, `canokey-oath`, `canokey-openpgp`,
  `canokey-admin`, `canokey-ndef`, `canokey-ctap`) — protocol logic; applets
  never depend on each other for key formats (`canokey-key` owns shared
  public-key encodings).
- `canokey` — the facade: re-exports plus probe orchestration.
- `canokey-c` — the experimental C ABI: opaque profile/operation handles,
  caller-owned POD errors, query-size/copy getters.

Selected-context access (`Access::Existing` in PIV and Admin, `*_selected`
factories, NDEF/CTAP profile-free entries) lets callers hold one card
transaction across operations without repeated SELECT/VERIFY. Card-controlled
parsing is bounded; malformed responses return typed errors instead of
panicking; PINs, keys and APDU payloads are redacted from Debug and zeroized.

## Design documents (normative)

- [API contracts](design/api-design.md) — ownership, byte formats, state
  requirements, access policies, status-word classification and binding rules
  for every public API surface.
- [Reference evidence](design/references.md) — pinned canokey-core firmware and
  consumer sources behind every encoding and version rule; distinguishes
  evidence from assumption.

Design changes must keep these two files in sync with the code.

## User guides (integration)

- [Console/Dart integration sketch](guides/console-integration.md) — future FRB
  boundary pseudocode for the Flutter console.
- [PKCS#11/C integration sketch](guides/pkcs11-integration.md) — C ABI usage
  pseudocode and the runnable C probe.

User documents describe how to consume implemented APIs; they never define
contracts. If a guide and a design document disagree, the design document wins.

## Project documents (repository root)

- [README](../README.md) — implemented features, build and validation commands.
- [AGENTS](../AGENTS.md) — contributor instructions.
