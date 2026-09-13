//! Explicit randomized Ed25519 signing of an empty message using an offline card.
#[allow(dead_code)]
mod support;
use canokey::{compatibility::*, piv::*, SecretBytes};
use support::{execute, AppResult, Card};
fn main() -> AppResult<()> {
    // Synthetic observations for this transcript; real applications use probe_device.
    let mut observations = DeviceObservations::new(b"3.1.0".to_vec());
    observations.piv_version = Some(PivApplicationVersion([5, 7, 0]));
    observations.algorithm_config = Some(AlgorithmConfig::parse(&[
        1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x54, 0x55, 0x56, 0x57,
    ])?);
    let profile = DeviceProfile::from_observations(observations)?;
    let operation = sign_streaming(
        &profile,
        Slot::Signature,
        StreamingSignInput::Ed25519Randomized(SecretBytes::default()),
        Access::Pin(Pin::from_bytes(b"123456")?),
        Default::default(),
    )?;
    drop(profile);
    let mut reply = vec![0x7c, 66, 0x82, 64];
    reply.extend([0x42; 64]);
    reply.extend([0x90, 0]);
    let mut card = Card::new(&[
        (&[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8], &[0x90, 0]),
        (b"\x00\x20\x00\x80\x08123456\xff\xff", &[0x90, 0]),
        (&[0, 0x87, 0xff, 0x9c, 6, 0x7c, 4, 0x82, 0, 0x81, 0], &reply),
    ]);
    let signature = execute(&mut card, operation)?;
    println!(
        "signature: {:?}, {:?}, {} bytes",
        signature.algorithm(),
        signature.encoding(),
        signature.as_bytes().len()
    );
    card.finish()
}
