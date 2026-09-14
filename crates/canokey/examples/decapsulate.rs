//! Offline ML-KEM-768 decapsulation: caller-owned profile, operation and transport.
#[allow(dead_code)]
mod support;
use canokey::{piv, probe_device, SecretBytes};
use support::{execute, AppResult, Card};

fn main() -> AppResult<()> {
    // Probe the synthetic device, including its configurable ML-KEM wire ID (57).
    let mut card = Card::new(&[
        (&[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0, 0], &[0x90, 0]),
        (&[0, 0x31, 0, 0, 0], b"3.1.0\x90\x00"),
        (&[0, 0x31, 1, 0, 0], &[0x6d, 0]),
        (&[0, 0x32, 0, 0, 0], &[0x6d, 0]),
        (&[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8, 0], &[0x90, 0]),
        (&[0, 0xfd, 0, 0, 0], &[5, 7, 0, 0x90, 0]),
        (
            &[0, 0xee, 1, 0, 0],
            &[
                1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x54, 0x55, 0x56, 0x57, 0x90, 0,
            ],
        ),
    ]);
    let profile = execute(&mut card, probe_device(Default::default())?)?;
    card.finish()?;

    // Fixture only: production ciphertext comes from the caller's encapsulation.
    let operation = piv::decapsulate(
        &profile,
        piv::Slot::KeyManagement,
        SecretBytes::new(vec![0x42; 1088]),
        piv::Access::Pin(piv::Pin::from_bytes(b"123456")?),
        Default::default(),
    )?;
    drop(profile);

    // Expected raw wire traffic belongs to the demo transport, never to callers
    // using real hardware: the operation produces SELECT, VERIFY and all chunks.
    let mut transcript = vec![
        (vec![0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8], vec![0x90, 0]),
        (
            b"\x00\x20\x00\x80\x08123456\xff\xff".to_vec(),
            vec![0x90, 0],
        ),
    ];
    let mut template = vec![0x7c, 0x82, 4, 0x46, 0x82, 0, 0x81, 0x82, 4, 0x40];
    template.extend([0x42; 1088]);
    let mut response = vec![0x7c, 34, 0x82, 32];
    response.extend([0x73; 32]);
    response.extend([0x90, 0]);
    let chunks = template.chunks(255).collect::<Vec<_>>();
    for (index, chunk) in chunks.iter().enumerate() {
        let last = index + 1 == chunks.len();
        let mut command = vec![
            if last { 0 } else { 0x10 },
            0x87,
            0x57,
            0x9d,
            chunk.len() as u8,
        ];
        command.extend_from_slice(chunk);
        transcript.push((
            command,
            if last {
                response.clone()
            } else {
                vec![0x90, 0]
            },
        ));
    }
    let slices = transcript
        .iter()
        .map(|(c, r)| (c.as_slice(), r.as_slice()))
        .collect::<Vec<_>>();
    let mut card = Card::new(&slices);
    let secret = execute(&mut card, operation)?;
    // Apply the application's KDF/key confirmation here; never print secret bytes.
    println!("shared secret: {} bytes", secret.len());
    drop(secret);
    card.finish()
}
