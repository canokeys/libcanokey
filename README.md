# libcanokey

libcanokey lets Rust and C applications use CanoKey over their own PC/SC, USB
or NFC connection. It builds command APDUs, handles chaining and parses card
responses. Your application sends each command and supplies the complete reply.

## Install

### Rust

Requires Rust 1.85 or later. Add the `canokey` crate for device probing and
the PIV, FIDO2, OpenPGP, OATH, Admin and NDEF APIs.

```sh
cargo add canokey@0.1.6
```

### C

Build from the release source with Cargo. Include `canokey.h` and link
against `canokey_c` from `target/release`. The C ABI is experimental and
covers PIV, OpenPGP, OATH and Admin. [Release source](https://github.com/canokeys/libcanokey/releases/tag/v0.1.6)
· [Header](crates/canokey-c/include/canokey.h)

```sh
cargo build --release -p canokey-c --locked
```

Run the offline C probe with `bash scripts/run-c-example.sh` to see the
operation loop, buffer-size queries and handle cleanup.
[C probe](crates/canokey-c/examples/probe.c) · [PKCS#11 integration](docs/guides/pkcs11-integration.md)

## Exchange APDUs

Use one raw exchange per loop iteration. The response must include SW1/SW2.
Hold the connection exclusively from `start` through completion and leave
61xx continuation and 6Cxx handling to libcanokey.

```rust,ignore
use canokey::{probe_device, ProbeOptions, Step};

let mut probe = probe_device(ProbeOptions::default())?;
let mut step = probe.start()?;
while step == Step::Exchange {
    let response = my_card_transmit(probe.command()?.as_bytes())?;
    step = probe.advance(&response)?;
}
let profile = probe.take_result()?;
```

Use the resulting profile to construct PIV operations. Refresh it after
reconnecting or changing the algorithm configuration. If an exchange fails,
drain or isolate outstanding I/O before reusing the connection. A failed write
can still have changed the card.
[Runnable Rust probe](crates/canokey/examples/probe.rs) · [API contracts](docs/design/api-design.md)

## Applets

| Applet | Operations |
| --- | --- |
| PIV | PIN/PUK, management authentication, keys and certificates, signing, RSA decryption, key agreement, ML-KEM decapsulation and F9 attestation-signer management |
| FIDO2/CTAP | Authenticator info, credential creation, assertions, U2F and hmac-secret. The `clientpin` feature adds ClientPIN, credential management, authenticator configuration and large blobs |
| OpenPGP | Key generation/import, signing, deciphering, key agreement, password management and certificates |
| OATH | HOTP and TOTP credentials, calculation and touch slots |
| Admin | Device identity, PIN, NFC/NDEF configuration, PASS slots and applet resets |
| NDEF | Capability container and message reads/writes |

Enable `x509` to inspect certificates or `serde` to serialize the inspection
results. Certificate trust and validity checks belong to the application.
[Rust API](https://docs.rs/canokey/0.1.6/canokey/) · [Certificate inspection](https://docs.rs/x509-info/0.1.1/)

## Firmware 4.0.x

| Algorithm | Applet | How to select it |
| --- | --- | --- |
| ML-DSA-44 | FIDO2 | Use COSE `-48` when the authenticator lists it in `getInfo` |
| ML-DSA-44 | PIV | Use `StreamingSignInput::MlDsa44` in Rust or `CNK_STREAM_MLDSA44` in C |
| ML-KEM-512 | PIV | Use `decapsulate_with_algorithm` in Rust or `cnk_piv_decapsulate_with_algorithm_new` in C |

PIV requires enabled algorithm IDs reported by the device. ML-DSA-44 and
ML-KEM-512 both support key generation, seed import and public-key export.
ML-KEM-512 decapsulation takes 768 ciphertext bytes and returns a 32-byte
shared secret. Use the profile to check support on older or unrecognized
firmware. [Firmware compatibility](docs/design/api-design.md#profiles-and-probing)

## Run an example

These examples use offline card responses. Pick one for your integration.

```sh
cargo run -p canokey --example probe --locked
cargo run -p canokey --example read_certificate --locked
cargo run -p canokey --example decapsulate --locked
```

[All Rust examples](crates/canokey/examples)

Licensed under [Apache-2.0](LICENSE).
