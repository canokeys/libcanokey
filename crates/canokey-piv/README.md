# canokey-piv

PIV card operations for [CanoKey](https://canokeys.org) devices: selection,
PIN/PUK management, management-key authentication (3DES/AES), key generation and
import, signing, key agreement, ML-KEM decapsulation, and object/certificate
I/O. Dedicated operations read and provision the P-256 F9 attestation signer.

The crate builds and parses APDUs only; your application owns the transport and
drives every exchange. Most applications should depend on the
[`canokey`](https://docs.rs/canokey) facade instead — it re-exports this crate as
`canokey::piv` and adds device probing. Depend on `canokey-piv` directly only when
you already hold a `DeviceProfile` and want PIV without the other applets.

- Documentation: <https://docs.rs/canokey-piv>
- Runnable examples: <https://github.com/canokeys/libcanokey/tree/main/crates/canokey/examples>
- API contracts: `docs/design/api-design.md` in the repository

License: Apache-2.0
