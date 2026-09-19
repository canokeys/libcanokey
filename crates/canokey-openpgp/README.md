# canokey-openpgp

OpenPGP card applet operations for CanoKey, in pure Rust: data-object and
certificate reads/writes, explicit PW1/PW3 password verification and
management, touch policies and retry limits, key generation and import with
SPKI public-key export, signing, PKCS#1 v1.5 decipher and ECDH/X25519
derivation.

The crate only builds complete command APDUs and parses complete responses
(data plus status words). Callers own the transport: send each command, return
each response, and hold the connection exclusively until the operation
finishes. There is no I/O, async runtime, credential cache or mutable global
state. PW1-sign and PW1-other are independent authorization modes, passwords
are always verified explicitly, and failed operations are never retried
automatically.

Most applications should depend on the
[`canokey`](https://crates.io/crates/canokey) facade crate instead; it probes
the device, builds the compatibility profile and re-exports this API. Depend
on `canokey-openpgp` directly only when you compose your own probing or need
the OpenPGP-specific types.

- API documentation: <https://docs.rs/canokey-openpgp>
- Repository: <https://github.com/canokeys/libcanokey>, with a facade-level
  example at `crates/canokey/examples/openpgp.rs` and offline transcripts in
  `crates/canokey-openpgp/tests/operations.rs`
- Full ownership, execution and error contracts: `docs/design/api-design.md`
  in the repository

License: Apache-2.0
