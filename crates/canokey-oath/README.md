# canokey-oath

Caller-owned OATH (TOTP/HOTP) operations for CanoKey devices. This crate builds
the OATH applet APDUs — credential management, access-code validation, and
one-time-code calculation — and parses the responses; your application owns the
transport and supplies every time challenge and fresh authentication randomness.
There is no I/O, runtime, credential cache, or mutable global state.

Most applications should depend on the [`canokey`] facade crate instead: it
re-exports this crate as `canokey::oath` and adds device probing. Depend on
`canokey-oath` directly only when you already hold a `DeviceProfile` and want
OATH without the facade.

## Documentation and examples

- API documentation: <https://docs.rs/canokey-oath>
- Runnable examples in the repository: `crates/canokey/examples/oath.rs`
  (caller-supplied TOTP time step with an offline transcript)
- Ownership, execution, and error contracts: `docs/design/api-design.md` in the
  repository.

Every operation is an owned, caller-driven state machine: `start`/`advance`
drive execution, `command` yields the APDU bytes to send, and getters never send
APDUs. Card status and parsing failures are retained as typed errors; failed or
lost responses are never replayed automatically. HOTP and increasing-TOTP state
can change on calculation.

License: Apache-2.0

[`canokey`]: https://docs.rs/canokey
