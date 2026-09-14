//! Historical wire transcripts. Real applications obtain observations via probe_device.
use canokey::{
    compatibility::{Capability, DeviceObservations, Support},
    oath, openpgp, DeviceProfile, Error, Operation,
};
fn run<T>(mut op: Operation<T>, transcript: &[(&[u8], &[u8])]) -> Result<T, Error> {
    op.start()?;
    for (command, reply) in transcript {
        assert_eq!(op.command()?.as_bytes(), *command);
        // Replace this fixture reply with one caller-owned transport exchange.
        op.advance(reply)?;
    }
    op.take_result()
}
fn main() -> Result<(), Error> {
    // Fixture identity, not an applet-reported synthetic version or a default.
    let mut observed = DeviceObservations::new(b"1.3".to_vec());
    observed.serial = Some(vec![1, 2, 3, 4]);
    let profile = DeviceProfile::from_observations(observed)?;
    assert_eq!(
        profile.capability(Capability::OathFullResponse).support,
        Support::Unsupported
    );
    let result = run(
        oath::operation(&profile, oath::Request::List, None, Default::default())?,
        &[
            (
                &[0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 5, 0x27, 0x21, 1, 0],
                &[0x90, 0],
            ),
            (
                &[0, 3, 0, 0, 255],
                &[0x71, 1, b'a', 0x75, 2, 0x21, 6, 0x90, 0],
            ),
            (&[0, 6, 0, 0, 255], &[0x69, 0x85]),
        ],
    )?;
    let oath::Outcome::Entries(entries) = result else {
        unreachable!()
    };
    assert_eq!(entries[0].digits, Some(6));
    // Pre-3.0.1 pagination can omit records: this count is an observation,
    // not a completeness guarantee. The library never recalculates HOTP to retry.
    println!("Observed {} OATH entry", entries.len());

    let result = run(
        openpgp::operation(
            &profile,
            openpgp::Request::ReadData(0x6e),
            None,
            Default::default(),
        )?,
        &[
            (
                &[0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1, 0],
                &[0x90, 0],
            ),
            // 6E has no outer wrapper; 73 uses a fixed-width definite BER length.
            (
                &[0, 0xca, 0, 0x6e, 0],
                &[0x73, 0x82, 0, 8, 0xc1, 6, 1, 8, 0, 0, 32, 2, 0x90, 0],
            ),
        ],
    )?;
    let openpgp::Outcome::Bytes(raw) = result else {
        unreachable!()
    };
    let fields = openpgp::ApplicationData::parse_with_profile(&profile, raw.as_bytes(), 4096)?;
    drop(profile); // Parsed data and operation results are independently owned.
    assert_eq!(
        fields.algorithm_attributes(openpgp::Slot::Signature)?,
        Some(&[1, 8, 0, 0, 32, 2][..])
    );
    Ok(())
}
