# canokey-piv

PIV card operations for [CanoKey](https://canokeys.org) devices: selection,
PIN/PUK management, management-key authentication (3DES/AES), key generation and
import, signing and key agreement (RSA, ECDSA/ECDH, Ed25519/X25519, SM2, ML-DSA,
ML-KEM), and object/certificate I/O including container parsing.

The crate builds and parses APDUs only; your application owns the transport and
drives every exchange. Most applications should depend on the
[`canokey`](https://docs.rs/canokey) facade instead — it re-exports this crate as
`canokey::piv` and adds device probing. Depend on `canokey-piv` directly only when
you already hold a `DeviceProfile` and want PIV without the other applets.

- Documentation: <https://docs.rs/canokey-piv>
- Runnable examples: <https://github.com/canokeys/libcanokey/tree/master/crates/canokey/examples>
- API contracts: `docs/design/api-design.md` in the repository

License: Apache-2.0
