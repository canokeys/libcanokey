# canokey-admin

Caller-owned operations for the CanoKey Admin applet: identity and
configuration reads, Admin PIN management, NFC/NDEF switches, and explicit
device and applet resets.

This crate only builds command APDUs and parses complete responses. Callers
own the transport, the connection, and all application state; the crate keeps
no connection, credential cache, or mutable global state. The Admin PIN is
always supplied explicitly — default credentials are never tried — and
destructive resets are sent only when the caller requests them.

Most applications should depend on the [`canokey` facade
crate](https://crates.io/crates/canokey) instead, which probes the device and
drives these operations. Depend on `canokey-admin` directly only when you
orchestrate the Admin conversation yourself.

## Documentation and examples

- API reference: <https://docs.rs/canokey-admin>
- The crate-level rustdoc contains a runnable quick-start example built from a
  recorded transcript; `tests/operations.rs` in the repository holds further
  golden transcripts and failure-path examples.
- Full API contracts: `docs/design/api-design.md` in the repository.

License: Apache-2.0
