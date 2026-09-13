//! Offline certificate container example, not an X.509 validation example.
mod support;
use canokey::{piv, probe_device};
use support::{execute, AppResult, Card, PROBE};
fn main() -> AppResult<()> {
    let mut transcript = PROBE.to_vec();
    transcript.extend_from_slice(&[
        (&[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8][..], &[0x90, 0][..]),
        (
            &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0][..],
            &[0x53, 9, 0x70, 2, 0x30, 0, 0x71, 1, 0, 0xfe, 0, 0x90, 0][..],
        ),
    ]);
    let mut card = Card::new(&transcript);
    let profile = execute(&mut card, probe_device(Default::default())?)?;
    let op = piv::read_certificate(
        &profile,
        piv::Slot::Authentication,
        piv::Access::None,
        Default::default(),
    )?;
    drop(profile); // The operation owns its configuration.
    let certificate = execute(&mut card, op)?;
    println!(
        "certificate payload: {} bytes; compressed: {}",
        certificate.der().len(),
        certificate.was_compressed()
    );
    // The tiny 30 00 payload tests framing only. A real application would pass
    // these bytes to its X.509 parser and apply its own trust policy.
    card.finish()
}
