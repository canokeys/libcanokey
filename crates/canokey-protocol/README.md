# canokey-protocol

Transport-free APDU conversations and caller-owned operations for
[CanoKey](https://canokeys.org) devices.

This crate is the wire-format foundation of the libcanokey host library. It
provides encoders and parsers for command and response APDUs (`apdu`), bounded
definite-length BER TLV codecs (`tlv`), typed protocol errors with command
context (`error`), and the owned, caller-driven `Operation` state machine
(`operation`) that drives an exchange of complete APDUs step by step. There is
no I/O, transport trait, runtime, threading, or mutable global state: the
library builds bytes and parses bytes, and the caller performs every transmit.

Most applications should depend on the
[`canokey`](https://crates.io/crates/canokey) facade crate instead, which
re-exports everything needed to talk to a device. Depend on `canokey-protocol`
directly only when you are building a new applet binding on top of the
operation model, or when you need the APDU/TLV codecs for other low-level
work.

- Documentation: <https://docs.rs/canokey-protocol>
- Repository: <https://github.com/canokeys/libcanokey>

Full API contracts (ownership, execution rules, error taxonomy) live in
[`docs/design/api-design.md`](https://github.com/canokeys/libcanokey/blob/main/docs/design/api-design.md)
in the repository.

License: Apache-2.0
