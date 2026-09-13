//! Offline probe example; no hardware or global state.
mod support;
use canokey::probe_device;
use support::{execute, AppResult, Card, PROBE};
fn main() -> AppResult<()> {
    let mut card = Card::new(PROBE);
    let profile = execute(&mut card, probe_device(Default::default())?)?;
    println!(
        "firmware: {}",
        String::from_utf8_lossy(profile.info().firmware_text())
    );
    card.finish()
}
