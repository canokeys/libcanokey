//! Offline TOTP calculation; the caller supplies time and owns the code bytes.
use canokey::{
    compatibility::{DeviceObservations, DeviceProfile},
    oath::{self, Algorithm, Format, Kind, Name, Outcome, Request},
    Step,
};
fn main() -> Result<(), canokey::Error> {
    let profile = DeviceProfile::from_observations(DeviceObservations::new(b"3.1.0".to_vec()))?;
    let mut op = oath::operation(
        &profile,
        Request::Calculate {
            name: Name::from_bytes(b"test")?,
            kind: Kind::Totp,
            algorithm: Algorithm::Sha1,
            challenge: Some(1u64.to_be_bytes()),
            format: Format::Truncated,
        },
        None,
        Default::default(),
    )?;
    drop(profile);
    let transcript: &[(&[u8], &[u8])] = &[
        (
            &[0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 5, 0x27, 0x21, 1],
            &[0x79, 3, 6, 0, 0, 0x71, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0],
        ),
        (
            &[
                0, 0xa2, 0, 1, 16, 0x71, 4, b't', b'e', b's', b't', 0x74, 8, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            &[0x76, 5, 6, 0, 0, 0, 42, 0x90, 0],
        ),
    ];
    let mut step = op.start()?;
    for (command, response) in transcript {
        assert_eq!(step, Step::Exchange);
        assert_eq!(op.command()?.as_bytes(), *command);
        step = op.advance(response)?;
    }
    assert_eq!(step, Step::Done);
    let Outcome::Calculations(codes) = op.take_result()? else {
        unreachable!()
    };
    let decimal = codes[0].decimal().expect("requested truncated code");
    assert_eq!(decimal.as_bytes(), b"000042");
    println!("received {} secret-owned decimal digits", decimal.len());
    Ok(())
}
