//! Offline OpenPGP signing: attributes, PW1-sign, then a single target command.
use canokey::{
    compatibility::{DeviceObservations, DeviceProfile},
    openpgp::{self, Access, Algorithm, Outcome, Password, PasswordReference, Request},
    SecretBytes, Step,
};
fn main() -> Result<(), canokey::Error> {
    let profile = DeviceProfile::from_observations(DeviceObservations::new(b"3.1.0".to_vec()))?;
    let mut op = openpgp::operation(
        &profile,
        Request::Sign(Algorithm::Ed25519, SecretBytes::new(b"hello".to_vec())),
        Some(Access {
            reference: PasswordReference::Pw1Sign,
            password: Password::from_bytes(b"654321")?,
        }),
        Default::default(),
    )?;
    drop(profile);
    let mut signature = vec![42; 64];
    signature.extend([0x90, 0]);
    let transcript: &[(&[u8], &[u8])] = &[
        (&[0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1], &[0x90, 0]),
        (
            &[0, 0xca, 0, 0x6e, 0],
            &[
                0x6e, 14, 0x73, 12, 0xc1, 10, 0x16, 0x2b, 6, 1, 4, 1, 0xda, 0x47, 15, 1, 0x90, 0,
            ],
        ),
        (b"\0\x20\0\x81\x06654321", &[0x90, 0]),
        (b"\0\x2a\x9e\x9a\x05hello", &signature),
    ];
    let mut step = op.start()?;
    for (command, response) in transcript {
        assert_eq!(step, Step::Exchange);
        assert_eq!(op.command()?.as_bytes(), *command);
        step = op.advance(response)?;
    }
    assert_eq!(step, Step::Done);
    let Outcome::Signature { algorithm, bytes } = op.take_result()? else {
        unreachable!()
    };
    println!("{algorithm:?} signature: {} bytes", bytes.len());
    Ok(())
}
