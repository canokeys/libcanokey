# libcanokey

[![CI](https://github.com/canokeys/libcanokey/actions/workflows/ci.yml/badge.svg)](https://github.com/canokeys/libcanokey/actions/workflows/ci.yml)

A Rust host-side library for [CanoKey](https://canokeys.org) devices. It builds the
command APDUs for each on-key applet (PIV, OpenPGP, OATH, FIDO2/CTAP, Admin, NDEF)
and parses the responses — you bring the transport (PC/SC, USB, NFC) and drive each
exchange. There is no runtime, no background thread, no credential cache and no
mutable global state, so it embeds cleanly in desktop apps, mobile apps (via FRB)
and C programs. A C ABI is available as `canokey-c` (experimental).

## Quick start (Rust)

Add the facade crate:

```sh
cargo add canokey
```

Every operation follows the same pattern: construct it, then loop over
`start`/`command`/`advance`, performing one raw transport transmit per iteration:

```rust,ignore
use canokey::{probe_device, ProbeMode, ProbeOptions, Step};

let mut op = probe_device(ProbeOptions {
    mode: ProbeMode::Piv, ..Default::default()
})?;
let mut step = op.start()?;
while step == Step::Exchange {
    // One raw transmit of your own: PC/SC SCardTransmit, USB CCID, NFC, ...
    let response = my_card_transmit(op.command()?.as_bytes())?;
    step = op.advance(&response)?; // response data including SW1/SW2
}
let profile = op.take_result()?; // owned; independent of the operation
```

Runnable offline versions of this loop (with fixture transcripts you can replace
with real I/O) live in [crates/canokey/examples](crates/canokey/examples).

## Quick start (C)

C applications link `canokey-c` and include
[`include/canokey.h`](crates/canokey-c/include/canokey.h). The runnable example
[probe.c](crates/canokey-c/examples/probe.c) shows size queries, profile transfer
and cleanup; build and run it with `bash scripts/run-c-example.sh`. The C ABI is
experimental. See the [PKCS#11 integration guide](docs/guides/pkcs11-integration.md)
for a complete session sketch.

## How it works

The library never touches a device itself. Your application owns the connection
and follows five rules:

- Implement one raw transmit: send a complete command APDU, return the complete
  response **including SW1/SW2**.
- Hold an exclusive connection lease for the whole operation loop.
- Disable transport-level continuation (61xx/6Cxx handling) and retries — the
  core performs those itself and must see the card's exact words.
- Getters never send APDUs; only `start`/`advance` advance the exchange.
- On I/O failure, drop the operation and drain or isolate pending I/O before
  reusing the connection. Dropping or cancelling never rolls back card effects.

## Features by applet

**PIV** — selection, PIN status/verification/logout, PIN/PUK change and unblock;
external/mutual 3DES or AES-192 management authentication with caller-supplied
challenges; authenticated object/certificate writes and management-key replacement;
PIN-managed protection validation/finalization with explicit PUK blocking; key
rotation maintaining PRINTED. Object/certificate reads with bounded gzip decoding,
certificate deletion, metadata and algorithm-configuration reads; compact directory
with entry diagnostics and UTF-16 container names; key move/delete; explicit PIN/PUK
retry reset; attestation DER; explicit reset of a blocked PIV application. Key
generation/import (P-256/P-384/P-521/secp256k1/SM2 scalars, RSA CRT, Ed25519/X25519/ML
seeds) with public-key SPKI export. Classic RSA/ECDSA/SM2/Ed25519 signing with DER/P1363
conversion; explicit ML-DSA (empty context), randomized Ed25519 and SM2 full-message
streaming signing, including empty messages; raw RSA decryption, ECDH
(P-256/P-384/P-521/secp256k1), X25519, ML-KEM-768 decapsulation and SM2 agreement
with pre-exchanged peer keys. Classic PIV hashing/padding and postprocessing KDF
remain caller responsibilities. Batch requests run under one SELECT and retain
completed results after a later failure.

**OpenPGP** — data-object/certificate reads and writes, separate PW1-sign/PW1-other
modes, password/reset management, explicit policies/fingerprints/timestamps, key
generation/import, shared SPKI export, signatures, PKCS#1 v1.5 decipher and
ECDH/X25519.

**OATH** — SELECT/access-code validation, PBKDF2 password derivation, credential
CRUD, full/truncated calculations and paged results with explicit HOTP/touch markers.
Set-default marks an HOTP credential as the touch keyboard-emulation default
(two-slot/append-enter dialect only on firmware 3.0.0+). The vendor extension
commands (GET SERIAL, HMAC-SHA1 challenge-response from a PASS slot) provide the
KeePassXC interop path on firmware 3.1.0.

**CTAP/FIDO2** — ISO 7816 transport envelope (explicit FIDO2 selection, `80 10`
message wrap, `80 C0` continuation) plus a typed CTAP2 client: strict canonical
CBOR, COSE key and authenticatorData parsing, getInfo/makeCredential/getAssertion/
reset/selection. The `clientpin` feature (default in `canokey-ctap`, opt-in on the
facade) adds ClientPIN protocols 1/2, credential management with bounded enumeration,
authenticatorConfig and fragmented largeBlobs. Raw CTAP1/U2F register/authenticate/
check-only/version commands are ungated; the hmac-secret extension covers the
makeCredential declaration and the encrypted salt exchange (including the CanoKey
hmac-secret-mc variant). WebAuthn ceremonies (clientDataJSON, attestation trust,
rpId policy) remain host-side.

**Admin** — identity/storage/configuration reads, PIN, NFC/NDEF and CTAP SM2
configuration, explicit applet/device resets; configuration patches retain confirmed
writes on failure. `admin::operation_with_access` (`Access::Existing`) reuses the
caller's selected Admin transaction without SELECT or implicit VERIFY. Typed PASS
slots read both touch slots (Off/Static/HmacSha1/Oath/Unknown) and write Off,
static-password or HMAC-SHA1 configurations.

**NDEF** — capability-container reads and chunked message read/replace with
zero-NLEN-first crash-consistent writes; profile-free.

**Cross-cutting** — minimal/PIV device probing with firmware and PIV version
separation; observed algorithm IDs with explicit Supported/Unsupported/Unknown
evidence; optional X.509 certificate inspection (see below).

## Firmware compatibility

Audited firmware layouts 1.3–3.1.0 are covered with per-operation gates. Legacy
OATH commands, OpenPGP DO framing and Admin configuration fields are selected from
the actual firmware version; unknown base versions never enable mutations, and
development builds follow their declared numeric base version. Every factory checks
required capability evidence. PIV `sign_streaming` handles ML-DSA and empty Ed25519
messages explicitly; SM2 initiators require PIN Never/Once and peer keys supplied at
construction. See [compatibility contracts](docs/design/api-design.md#profiles-and-probing)
for the model and each applet's historical restrictions. Validation uses pinned sources
and offline transcripts; hardware checks and consumer integration remain separate.

## Examples

Install rustup; the repository selects Rust 1.85.1 (MSRV 1.85). All examples use
synthetic offline transcripts and check emitted commands. Test credentials,
challenges and certificate payloads are fixtures, not production inputs.

| Example | Demonstrates |
| --- | --- |
| [historical](crates/canokey/examples/historical.rs) | Firmware 1.3 OATH LIST and profile-aware OpenPGP field parsing |
| [openpgp](crates/canokey/examples/openpgp.rs) | Observed key attributes, explicit PW1-sign and owned signature |
| [oath](crates/canokey/examples/oath.rs) | Caller-supplied TOTP time step and owned code bytes |
| [admin](crates/canokey/examples/admin.rs) | Explicit PIN and configuration patch under one SELECT |
| [probe](crates/canokey/examples/probe.rs) | Caller-owned device profile |
| [read_certificate](crates/canokey/examples/read_certificate.rs) | Operation and result lifetimes |
| [write_certificate](crates/canokey/examples/write_certificate.rs) | Mutual authentication followed by PUT DATA |
| [decapsulate](crates/canokey/examples/decapsulate.rs) | Algorithm discovery, PIN, chained ML-KEM ciphertext and owned secret |
| [sign_streaming](crates/canokey/examples/sign_streaming.rs) | Explicit randomized Ed25519 signing of an empty message |
| [batch](crates/canokey/examples/batch.rs) | Successful preceding results after a later failure |
| [C probe](crates/canokey-c/examples/probe.c) | Size queries, profile transfer and cleanup |

```sh
cargo run -p canokey --example admin --locked
cargo run -p canokey --example oath --locked
cargo run -p canokey --example openpgp --locked
cargo run -p canokey --example batch --locked
bash scripts/run-c-example.sh
```

Boundary sketches for real integrations:
[Console/Dart](docs/guides/console-integration.md),
[PKCS#11/C](docs/guides/pkcs11-integration.md).

## Certificate inspection

Enable `canokey/x509` for parsing, or `canokey/serde` for optional serialization.
Default builds omit the parser; applications choose their own serializers or FRB DTOs.

```rust,ignore
let info = canokey::x509::parse_der(certificate.der(), Default::default())?;
// With canokey/serde and the application's serde_json dependency:
let json = serde_json::to_string(&info.summary())?;
```

The [x509-info documentation](https://github.com/canokeys/x509-info) owns certificate
models, CLI formats and schema. Parsing does not verify certificate trust or validity.

## Crate map

Rust applications depend on **`canokey`**; C applications link **`canokey-c`**.
Depend on a lower-level crate directly only when you need it without the facade.

| Crate | Responsibility |
| --- | --- |
| [`canokey`](crates/canokey) | Facade: re-exports all applets plus device probing |
| [`canokey-c`](crates/canokey-c) | Experimental C ABI (copied descriptors, opaque handles) |
| [`canokey-piv`](crates/canokey-piv) | PIV operations and certificate container parsing |
| [`canokey-openpgp`](crates/canokey-openpgp) | OpenPGP data, passwords, policies and key operations |
| [`canokey-oath`](crates/canokey-oath) | OATH access, credentials and calculations |
| [`canokey-ctap`](crates/canokey-ctap) | CTAP/FIDO2 envelope and CTAP2 client (ClientPIN, credential management) |
| [`canokey-admin`](crates/canokey-admin) | Admin reads, configuration, PIN and explicit resets |
| [`canokey-ndef`](crates/canokey-ndef) | NDEF capability reads and crash-consistent message writes |
| [`canokey-protocol`](crates/canokey-protocol) | APDU/TLV codecs, owned operations, limits, errors, secret buffers |
| [`canokey-compat`](crates/canokey-compat) | Immutable profiles, capability evidence, firmware rules |
| [`canokey-key`](crates/canokey-key) | Shared public-key TLV fields and pure SPKI export |

The facade optionally re-exports the independent crates.io package
[`x509-info`](https://github.com/canokeys/x509-info) 0.1.1. The full architecture
and layering rationale live in the [documentation map](docs/README.md).

## Building and contributing

```sh
cargo fmt --all --check
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo build --workspace --locked
cargo build -p canokey --all-features --target wasm32-unknown-unknown --locked
python3 scripts/check-dependencies.py
python3 scripts/check-licenses.py
bash scripts/test-c-abi.sh
```

CI checks native/wasm builds, examples, doctests, strict rustdoc/clippy, dependency
boundaries, licenses and C/C++ linking. Open `target/doc/canokey/index.html` for
public API documentation. Contribution rules (language, architecture, checks,
commits) are in [AGENTS.md](AGENTS.md).

## Documentation

- [Documentation map](docs/README.md): design documents vs user guides, with an
  architecture overview.
- [API contracts](docs/design/api-design.md): ownership, execution and binding rules.
- [Reference evidence](docs/design/references.md): pinned firmware and consumer sources.
- The companion [canokey-pkcs11 migration](https://github.com/canokeys/canokey-pkcs11/blob/codex/libcanokey/docs/libcanokey-piv-migration-plan.md)
  validates the PIV C ABI against native Windows hardware. Console/ckman and
  general Python bindings are separate projects, out of scope for this repository.

Copyright 2026 canokeys.org. Licensed under [Apache-2.0](LICENSE). Each workspace
crate inherits the metadata and includes a copy of the root license for packaging.
Third-party dependencies and reference repositories retain their own licenses.
