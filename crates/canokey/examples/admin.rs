//! Offline Admin patch: the caller owns the profile, PIN, operation and I/O loop.
use canokey::{
    admin::{self, ConfigurationPatch, Pin, Request},
    compatibility::{DeviceObservations, DeviceProfile},
    Step,
};
fn main() -> Result<(), canokey::Error> {
    let profile = DeviceProfile::from_observations(DeviceObservations::new(b"3.1.0".to_vec()))?;
    let mut op = admin::operation(
        &profile,
        Request::Configure(ConfigurationPatch {
            led_on: Some(false),
            ..Default::default()
        }),
        Some(Pin::from_bytes(b"654321")?),
        Default::default(),
    )?;
    drop(profile);
    let transcript: &[(&[u8], &[u8])] = &[
        (&[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0], &[0x90, 0]),
        (b"\0\x20\0\0\x06654321", &[0x90, 0]),
        (&[0, 0x42, 0, 0, 0], &[1, 0, 0, 1, 1, 0x3f, 0x90, 0]),
        (&[0, 0x40, 1, 0], &[0x90, 0]),
    ];
    let mut step = op.start()?;
    for (command, response) in transcript {
        assert_eq!(step, Step::Exchange);
        assert_eq!(op.command()?.as_bytes(), *command);
        // One raw application I/O call replaces the fixture response.
        step = op.advance(response)?;
    }
    assert_eq!(step, Step::Done);
    let result = op.take_result()?;
    println!(
        "confirmed writes: {}; reprobe: {}",
        result.confirmed_writes, result.reprobe_required
    );
    Ok(())
}
