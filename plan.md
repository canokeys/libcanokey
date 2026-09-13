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

Admin, OATH and OpenPGP factories now select audited historical layouts from actual
firmware with independent feature gates. Legacy CTAP SM2 identifiers remain explicit
raw native-layout bytes until byte order is established for the target hardware.
Hardware/usbip checks remain necessary to
establish interoperability across firmware and transport variants.

Consumer integration, FIDO/CTAP operations and Python bindings require separate
scope. Integrate PKCS#11 first, then Console/ckman, with one connection lease and
transport continuation/retries disabled. Freeze the C ABI after consumer validation.

Follow [AGENTS.md](AGENTS.md) for implementation checks and staged commits. Retain
existing APIs and extend bindings/examples with future protocol additions.
