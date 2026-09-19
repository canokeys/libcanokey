# canokey-key

Shared CanoKey public key encodings and SPKI conversion.

CanoKey PIV and OpenPGP applets return public keys as simple inner TLV fields
(RSA modulus/exponent, or an uncompressed point). This crate parses those
fields into an owned `PublicKey` with encoding and size checks, and encodes
any `PublicKey` as canonical DER SubjectPublicKeyInfo
(`PublicKey::to_spki_der`) using RustCrypto ASN.1 types. Everything here is
pure: no device access, no cryptographic operations, and no trust or
key-validity claims beyond encoding checks.

Most applications should depend on the
[`canokey`](https://crates.io/crates/canokey) facade crate instead, which
returns keys through the PIV and OpenPGP applets. Depend on `canokey-key`
directly only when you hold public-key material obtained elsewhere and need
SPKI/DER export, or when you are writing an applet binding that must parse
CanoKey public-key TLV fields.

- Documentation: <https://docs.rs/canokey-key>
- Repository: <https://github.com/canokeys/libcanokey>

The shared key-encoding contract lives in
[`docs/design/api-design.md`](https://github.com/canokeys/libcanokey/blob/main/docs/design/api-design.md)
in the repository.

License: Apache-2.0
