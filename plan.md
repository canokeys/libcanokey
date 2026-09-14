# Remaining work

[README](README.md) lists implemented features and examples;
[API contracts](docs/api-design.md) define ownership and protocol behavior.

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

- Validate Admin/OATH/OpenPGP/PIV against hardware or usbip on the ckman catalog:
  1.3, 1.5.2, 1.6.1, 1.6.2, 2.0.x, 3.0.x and 3.1.0. Check authentication,
  legacy TLV lengths, pagination boundaries, command chaining and cancellation.
  Offline transcript tests establish command behavior, not device interoperability.
- Establish legacy CTAP SM2 integer byte order for each target before offering
  typed identifier conversion; the existing raw nine-byte interface preserves data.
- Split PIV Ed/X read/generate/import/private-operation evidence if enabling more
  pre-3.0.1 operations. Keep known signing/import bug gates until independently tested.

Consumer integration, FIDO/CTAP operations and Python bindings require separate
scope. Integrate PKCS#11 first, then Console/ckman, with one connection lease and
transport continuation/retries disabled. Freeze the C ABI after consumer validation.

Follow [AGENTS.md](AGENTS.md) for implementation checks and staged commits. Retain
existing APIs and extend bindings/examples with future protocol additions.
