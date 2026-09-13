//! Executable transcript example. Replace the fixture with application-owned I/O.
use canokey::{probe_device, ProbeMode, ProbeOptions, Step};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut op = probe_device(ProbeOptions {
        mode: ProbeMode::Minimal,
        ..Default::default()
    })?;
    let responses: &[&[u8]] = &[
        &[0x90, 0],
        b"3.1.0\x90\x00",
        b"CanoKey\x90\x00",
        &[1, 2, 3, 4, 0x90, 0],
    ];
    let mut responses = responses.iter();
    let mut step = op.start()?;
    while step == Step::Exchange {
        // Send op.command()?.as_bytes() through your transport, retaining SW1/SW2.
        let response = responses.next().ok_or("fixture exhausted")?;
        step = op.advance(response)?;
    }
    let profile = op.take_result()?;
    println!(
        "firmware: {}",
        String::from_utf8_lossy(profile.info().firmware_text())
    );
    Ok(())
}
