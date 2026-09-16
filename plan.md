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

Console/ckman and general Python bindings remain separate scope. The CTAP
ISO 7816 transport envelope (FIDO2 selection, message wrap and continuation) is
implemented; CBOR interpretation, ClientPin and WebAuthn ceremonies remain
host-side consumer scope. The NDEF and PASS applets are now covered by the
library, pending the same hardware validation as the other applets above.
Consumers must retain one connection lease per operation and disable
transport continuation/retries. The C ABI remains experimental.

Follow [AGENTS.md](AGENTS.md) for implementation checks and staged commits. Retain
existing APIs and extend bindings/examples with future protocol additions.
