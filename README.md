# libcanokey

A Rust host protocol library for CanoKey. It produces APDUs and consumes complete responses; the caller owns connections, transport, scheduling, and application state. Unpublished 0.1 development workspace; the C ABI is experimental.

## Crates and dependencies

Most Rust applications should depend on **`canokey`**. C applications link **`canokey-c`**. A future Console FRB wrapper should depend directly on `canokey`, without going through C.

| Crate | Responsibility | Direct workspace dependencies |
| --- | --- | --- |
| `canokey-protocol` | APDU/TLV codecs, owned `Operation<T>`, ISO continuation/chaining, limits, errors, zeroized buffers | None |
| `canokey-compat` | Immutable device profiles, capability evidence, firmware rules and algorithm IDs | protocol |
| `canokey-admin` | Minimal read-only Admin bootstrap command builders | protocol |
| `canokey-piv` | PIV operations and certificate container parsing | protocol, compat |
| `canokey` | Application-facing facade: re-exports lower layers and orchestrates device probing | protocol, compat, admin, piv |
| `canokey-c` | C ABI: converts descriptors, dispatches operations, copies results | canokey |

Dependency arrows point from consumer to dependency:

```mermaid
graph TD
    C[canokey-c] --> F[canokey]
    F --> A[canokey-admin]
    F --> P[canokey-piv]
    F --> K[canokey-compat]
    F --> R[canokey-protocol]
    P --> K
    P --> R
    K --> R
    A --> R
```

`protocol` knows nothing about firmware or applets. `compat` never calls an applet; putting probe orchestration in the facade avoids a dependency cycle. `admin` currently contains only bootstrap builders, so it does not yet need compat. Bindings adapt ownership and types without duplicating protocol state. There is no transport crate or mutable global state.

## Implemented scope

- Owned operation state machine, bounded ISO GET RESPONSE, safe one-time Le correction, short command chaining, BER TLV, and secret buffers.
- Firmware/PIV version separation, capability evidence, conservative unknown-version handling, observed algorithm IDs, and narrow legacy object quirks.
- Minimal/PIV read-only probe; PIV SELECT, PIN status/verify/logout, PIN/PUK changes, PIN unblock, object reads with optional PIN, and certificate reads.
- Certificate container parsing and bounded gzip decompression. `Certificate::der()` returns the payload; X.509 syntax, signatures, and trust validation remain application responsibilities.
- Experimental C ABI 0.1: probe, PIN verification/status, public object/certificate reads, typed errors, and copy getters. Only profile/operation handles; see [header](crates/canokey-c/include/canokey.h).

Management-key authentication, writes, metadata, key generation/import/sign/decrypt/derive, Batch, full Admin, OATH, OpenPGP, and Python/FRB bindings are **not implemented**. No consumer repository has been integrated. Compatibility is based on host sources and offline transcripts, not hardware/usbip validation.

## Runnable examples

Install rustup; the repository selects Rust 1.85.1 (MSRV 1.85). From the repository root:

```sh
cargo run -p canokey --example probe --locked
# firmware: 9.0.0
cargo run -p canokey --example read_certificate --locked
# certificate payload: 2 bytes; compressed: false
bash scripts/run-c-example.sh
# firmware: 3.1.0
```

These examples run **offline** and compare every emitted command against a deterministic transcript. The synthetic 9.0.0 firmware demonstrates conservative fallback, not verified firmware support. The two-byte certificate payload demonstrates framing and is not a valid X.509 certificate. The C script requires a Unix shell, Python 3, and a C compiler; it compiles and links the actual library.

- [Rust probe](crates/canokey/examples/probe.rs): obtain a caller-owned profile.
- [Rust certificate read](crates/canokey/examples/read_certificate.rs): construct an operation, release its source profile, drive it, and retain the result.
- [Rust application executor](crates/canokey/examples/support/mod.rs): replace the fixture exchange with application-owned raw I/O.
- [C probe](crates/canokey-c/examples/probe.c): size queries, handle transfer, command validation, and cleanup on failure.

For real hardware, hold one exclusive connection lease across the entire operation. Send `command()` bytes and supply response data **including SW1/SW2** to `advance()`. Disable transport continuation/retries. Getters never send APDUs. An application I/O error drops/closes the operation; drain or isolate outstanding I/O before reusing the connection. See the [Console](docs/console-integration.md) and [PKCS#11](docs/pkcs11-integration.md) boundary examples.

## Rust API documentation

All six crates document public types, fields, methods and factories in rustdoc, including ownership, byte formats, lifecycle errors, and FFI safety. Start with the facade's quick start, then follow its `piv` and `compatibility` re-exports. The low-level operation documentation includes a complete caller-driven exchange example.

```sh
cargo doc --workspace --no-deps --locked --open
# Or open target/doc/canokey/index.html after building without --open.
cargo test --workspace --doc --locked
```

Each crate denies missing public documentation. CI builds rustdoc with warnings treated as errors, and the workspace test command executes the documentation examples. Dependency choices for future cryptography and key formats are recorded in [API design](docs/api-design.md#dependency-reuse); use established primitives with minimal features and caller-supplied randomness.

## Validation

```sh
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo build -p canokey --target wasm32-unknown-unknown --locked
python3 scripts/check-dependencies.py
bash scripts/test-c-abi.sh
```

Local validation covers 25 Rust tests and 8 executable rustdoc examples, including malformed input, resource limits, gzip corruption/expansion, ownership, and deterministic parser fuzz smoke; Linux C/C++ checks, examples, wasm, and dependency boundaries also pass. CI additionally targets macOS and Windows; local checks do not establish remote CI or hardware results.

Core external dependencies provide zeroization and pure Rust gzip decoding, with no platform transport or async runtime. Cargo.lock is tracked; `references/`, build outputs, and caches are ignored.

## Documentation

- [Plan](plan.md): milestones, remaining scope, acceptance.
- [API design](docs/api-design.md): ownership and protocol contracts, including explicitly marked future APIs.
- [Reference sources](docs/references.md): pinned upstream evidence.
- [Contributor instructions](AGENTS.md): English repository language, architecture, checks, and commits.

## License

Copyright 2026 canokeys.org.

Licensed under the [Apache License, Version 2.0](LICENSE). The root license applies to all original workspace crates, examples, and documentation. Each crate inherits the SPDX identifier, license file, authors, and homepage from workspace metadata; Cargo includes the shared license file in packaged crates. Third-party dependencies and read-only reference repositories retain their own licenses.
