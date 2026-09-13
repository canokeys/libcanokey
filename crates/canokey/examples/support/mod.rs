//! Application-owned executor and deterministic transport, outside the library.
use canokey::{Operation, Step};
use std::collections::VecDeque;
pub type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

pub struct Card {
    transcript: VecDeque<(&'static [u8], &'static [u8])>,
}
impl Card {
    pub fn new(transcript: &[(&'static [u8], &'static [u8])]) -> Self {
        Self {
            transcript: transcript.iter().copied().collect(),
        }
    }
    fn exchange(&mut self, command: &[u8]) -> AppResult<Vec<u8>> {
        let (expected, response) = self.transcript.pop_front().ok_or("unexpected exchange")?;
        if command != expected {
            return Err("command differs from transcript".into());
        }
        // Replace this fixture lookup with one raw PCSC/USB/NFC exchange.
        // Preserve SW1/SW2; disable transport-level continuation and retries.
        Ok(response.to_vec())
    }
    pub fn finish(self) -> AppResult<()> {
        if !self.transcript.is_empty() {
            return Err("unused transcript entries".into());
        }
        Ok(())
    }
}

pub fn execute<T>(card: &mut Card, mut op: Operation<T>) -> AppResult<T> {
    // The application holds an exclusive connection lease for this whole call.
    let mut step = op.start()?;
    while step == Step::Exchange {
        let response = card.exchange(op.command()?.as_bytes())?;
        step = op.advance(&response)?;
    }
    // An I/O/protocol error also drops op; no global cleanup is needed.
    Ok(op.take_result()?)
}

pub const PROBE: &[(&[u8], &[u8])] = &[
    (&[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0], &[0x90, 0]),
    (&[0, 0x31, 0, 0, 0], b"9.0.0\x90\x00"),
    (&[0, 0x31, 1, 0, 0], b"CanoKey\x90\x00"),
    (&[0, 0x32, 0, 0, 0], &[1, 2, 3, 4, 0x90, 0]),
    (&[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8], &[0x90, 0]),
    (&[0, 0xfd, 0, 0, 0], &[5, 7, 0, 0x90, 0]),
];
