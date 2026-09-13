//! Offline mutual-authentication and certificate-write transcript.
mod support;
use canokey::{piv, probe_device, SecretBytes};
use support::{execute, AppResult, Card, PROBE};
fn main() -> AppResult<()> {
    // These public known-answer inputs are fixtures, never production credentials
    // or randomness. A real application obtains a fresh challenge from its CSPRNG.
    let key: Vec<u8> = (0..24).collect();
    let authentication = piv::ManagementAuthentication::mutual(
        piv::ManagementKey::from_bytes(piv::ManagementKeyAlgorithm::Aes192, &key)?,
        &[0; 16],
    )?;
    let mut transcript = PROBE.to_vec();
    transcript[1].1 = b"3.1.0\x90\x00";
    transcript.push((&[0, 0xee, 1, 0, 0], &[0x6d, 0]));
    transcript.extend_from_slice(&[
        (&[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8], &[0x90, 0]),
        (
            &[0, 0x87, 0x0a, 0x9b, 4, 0x7c, 2, 0x80, 0],
            &[
                0x7c, 18, 0x80, 16, 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf,
                0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91, 0x90, 0,
            ],
        ),
        (
            &[
                0, 0x87, 0x0a, 0x9b, 38, 0x7c, 36, 0x80, 16, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x81, 16, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            &[
                0x7c, 18, 0x82, 16, 0x91, 0x62, 0x51, 0x82, 0x1c, 0x73, 0xa5, 0x22, 0xc3, 0x96,
                0xd6, 0x27, 0x38, 1, 0x96, 7, 0x90, 0,
            ],
        ),
        (
            &[
                0, 0xdb, 0x3f, 0xff, 16, 0x5c, 3, 0x5f, 0xc1, 5, 0x53, 9, 0x70, 2, 0x30, 0, 0x71,
                1, 0, 0xfe, 0,
            ],
            &[0x90, 0],
        ),
    ]);
    let mut card = Card::new(&transcript);
    let profile = execute(&mut card, probe_device(Default::default())?)?;
    let operation = piv::write_certificate(
        &profile,
        piv::Slot::Authentication,
        SecretBytes::new(vec![0x30, 0]),
        piv::Access::Management(authentication),
        Default::default(),
    )?;
    drop(profile);
    let result = execute(&mut card, operation)?;
    println!(
        "certificate written; profile effect: {:?}",
        result.profile_effect
    );
    // No transport is opened here and the two-byte payload tests framing only.
    // An application must invalidate its certificate cache after this mutation.
    card.finish()
}
