# canokey

Host-side protocol library for [CanoKey](https://canokeys.org) devices. This facade
crate re-exports every applet — PIV, OpenPGP, OATH, FIDO2/CTAP, Admin, NDEF — plus
device probing, and is the crate most Rust applications should depend on.

The library never performs I/O: it builds command APDUs and parses responses while
your application owns the transport (PC/SC, USB, NFC) and drives each exchange.
There is no runtime, no credential cache and no mutable global state.

```rust,ignore
use canokey::{probe_device, ProbeMode, ProbeOptions, Step};

let mut op = probe_device(ProbeOptions {
    mode: ProbeMode::Piv, ..Default::default()
})?;
let mut step = op.start()?;
while step == Step::Exchange {
    let response = my_card_transmit(op.command()?.as_bytes())?; // your raw transport call
    step = op.advance(&response)?; // response data including SW1/SW2
}
let profile = op.take_result()?;
```

Optional features: `x509` (certificate inspection), `serde` (serialization of
inspection results), `clientpin` (CTAP ClientPIN, credential management,
authenticatorConfig and largeBlobs). C applications use the `canokey-c` crate
instead.

- Documentation: <https://docs.rs/canokey>
- Repository, examples and guides: <https://github.com/canokeys/libcanokey>

License: Apache-2.0
