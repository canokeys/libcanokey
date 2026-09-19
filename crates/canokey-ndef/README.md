# canokey-ndef

NDEF message operations for CanoKey devices.

This crate builds the APDU sequences that select the CanoKey NDEF applet
(AID `D2 76 00 00 85 01 01`), read the capability container, and read or
replace the single NDEF message stored in its Type 4 Tag style data file
(two big-endian length bytes, then the message), in chunks of at most 240
bytes. It performs no I/O itself: the caller owns the transport and drives
each returned operation, and getters never send commands. Message writes are
crash-consistent — a zero length is written before the message chunks, so a
mid-write power loss leaves an empty message instead of a corrupt one. No
NDEF behaviour varies across firmware versions, so the factories are
profile-free.

## When to use this crate

Most applications should depend on the [`canokey`] facade crate instead,
which re-exports this API as `canokey::ndef` together with device probing
and the other applet crates. Depend on `canokey-ndef` directly only when you
need NDEF access without the rest of the facade.

[`canokey`]: https://docs.rs/canokey

## Documentation and examples

- API documentation: <https://docs.rs/canokey-ndef>
- Repository examples using offline transcripts:
  <https://github.com/canokeys/libcanokey#examples>
- Full ownership and execution contracts: `docs/design/api-design.md` in the
  repository.

License: Apache-2.0
