# Remaining work

[README](README.md) lists implemented features and examples;
[API contracts](docs/design/api-design.md) define ownership and protocol behavior.

## Firmware-dependent features

- **PIV ML-DSA context/prehash:** pinned firmware hardcodes an empty context and
  exposes no prehash mode. Enable only after a firmware protocol exists.
- **Interactive SM2 agreement:** current operations require peer keys up front.
  An interactive exchange needs an explicit input-suspension contract. PIN-always
  initiators also need firmware changes: VERIFY clears agreement state and step 1
  consumes PIN-always authorization.
- **OpenPGP KDF:** pinned firmware has no F9 KDF DO or configuration handler.
  Future support needs firmware evidence, typed S2K parameters and budgeted derivation.

## Compatibility and adoption

Admin migration now covers keyboard HID keymap and PASS configuration command
families, including typed keymap boundaries and C ABI request/result mapping.
Writes require explicit Admin PIN authentication; ordinary Admin operations
retain their SELECT-first behavior.

- Validate Admin/OATH/OpenPGP/PIV against hardware or usbip on the ckman catalog:
  1.3, 1.5.2, 1.6.1, 1.6.2, 2.0.x, 3.0.x and 3.1.0. Check authentication,
  legacy TLV lengths, pagination boundaries, command chaining and cancellation.
  Offline transcript tests establish command behavior, not device interoperability.
  Partial usbip coverage exists: the NDEF/PASS/OATH-set-default/Admin-Access/PIV-PQ
  feature set ran against canokey-usbip virtual hardware on firmware 3.1.0 (full
  suite, including ML-DSA/ML-KEM roundtrips), 3.0.0 (modern OATH set-default
  accepted; ML import correctly gated), and 2.0.1/1.5.2 (legacy OATH
  set-default dialect); the full ckman catalog above is not covered.
- Establish legacy CTAP SM2 integer byte order for each target before offering
  typed identifier conversion; the existing raw nine-byte interface preserves data.
- Split PIV Ed/X read/generate/import/private-operation evidence if enabling more
  pre-3.0.1 operations. Keep known signing/import bug gates until independently tested.

The companion PKCS#11 migration now validates the PIV C ABI through native
Windows hardware, transaction/failure contracts and the Windows minidriver.
It covers PIN/PUK recovery, management protection, supported key variants and
six-container certificate propagation. Native ARM64 runtime is excluded from
that acceptance; cross-builds are checked. See the companion
[migration acceptance](https://github.com/canokeys/canokey-pkcs11/blob/codex/libcanokey/docs/libcanokey-piv-migration-plan.md).

Console/ckman and general Python bindings remain separate scope. In CTAP,
both the ISO 7816 transport envelope (FIDO2 selection, message wrap and
continuation) and the CTAP2 client layer (strict canonical CBOR, typed
command operations, ClientPin protocols 1/2, credential management,
authenticatorConfig, largeBlobs, hmac-secret and the raw CTAP1/U2F commands)
are implemented in canokey-ctap; WebAuthn ceremony and relying-party logic
(clientDataJSON, attestation trust, rpId policy) remains host-side consumer
scope. The CTAP2 layer (getInfo, ClientPin v1+v2, makeCredential,
getAssertion with external ES256 and ML-DSA-65 verification, and credential
management including metadata-only) was validated against canokey-usbip
virtual hardware on firmware 3.1.0. The NDEF and PASS applets are now
covered by the library; they were validated on the same usbip runs described
in the compatibility section above. Consumers must retain one connection
lease per operation and disable transport continuation/retries. The C ABI
remains experimental.

Follow [AGENTS.md](AGENTS.md) for implementation checks and staged commits. Retain
existing APIs and extend bindings/examples with future protocol additions.
