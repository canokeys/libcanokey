# canokey-ctap

CTAP/FIDO2 client for [CanoKey](https://canokeys.org) devices: the ISO 7816
transport envelope (FIDO2 selection, `80 10` message wrap, `80 C0` continuation)
plus typed CTAP2 building blocks — strict canonical CBOR, COSE keys,
authenticatorData parsing, getInfo/makeCredential/getAssertion/reset/selection,
and the raw CTAP1/U2F commands.

Standalone operations try the private USB management AID required by firmware
3.1.2 on CCID/WebUSB, falling back to standard FIDO selection only on `6A82`
for older firmware and NFC. No CTAP command is replayed.

The default `clientpin` feature adds ClientPIN protocols 1/2, credential
management, authenticatorConfig and fragmented largeBlobs. WebAuthn ceremonies
(clientDataJSON, attestation trust, rpId policy) remain host-side.

The crate builds and parses messages only; your application owns the transport and
drives every exchange. Most applications should depend on the
[`canokey`](https://docs.rs/canokey) facade instead — it re-exports this crate as
`canokey::ctap` (where `clientpin` is opt-in). Depend on `canokey-ctap` directly
for standalone FIDO2 access.

- Documentation: <https://docs.rs/canokey-ctap>
- Repository and examples: <https://github.com/canokeys/libcanokey>

License: Apache-2.0
