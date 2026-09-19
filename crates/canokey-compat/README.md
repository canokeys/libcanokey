# canokey-compat

CanoKey firmware compatibility rules and immutable capability profiles.

This crate normalizes device observations (firmware text, PIV application
version, algorithm configuration, discovery warnings) into a caller-owned,
immutable `DeviceProfile`, and answers compatibility questions against an
audited firmware matrix covering releases 1.3 through 3.1.0. Every answer is a
`CapabilityStatus` pairing a three-valued `Support` decision with its
`Evidence` provenance; `Unknown` is deliberately distinct from `Unsupported`.
It also defines semantic `Algorithm` identifiers, firmware-version parsing,
and PIV wire-ID mappings. The crate performs no device I/O: probing a card is
the facade's job.

Most applications should depend on the
[`canokey`](https://crates.io/crates/canokey) facade crate instead, which
probes a device and builds a profile for you. Depend on `canokey-compat`
directly only when you construct a `DeviceProfile` manually from observations
you obtained yourself, or when you need to inspect capability evidence without
the facade.

- Documentation: <https://docs.rs/canokey-compat>
- Repository: <https://github.com/canokeys/libcanokey>

The full compatibility model lives in
[`docs/design/api-design.md`](https://github.com/canokeys/libcanokey/blob/main/docs/design/api-design.md#profiles-and-probing)
in the repository.

License: Apache-2.0
