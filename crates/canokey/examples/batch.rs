//! Offline Batch failure: completed results survive without replay or rollback.
mod support;
use canokey::{
    piv::{self, BatchItem, BatchRequest, ObjectId, Slot},
    probe_device,
};
use support::{drive, execute, AppResult, Card, PROBE};
fn main() -> AppResult<()> {
    let mut transcript = PROBE.to_vec();
    transcript.extend_from_slice(&[
        (&[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8][..], &[0x90, 0][..]),
        (
            &[0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 0][..],
            &[0x7e, 1, 0x42, 0x90, 0][..],
        ),
        (
            &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0][..],
            &[0x6a, 0x82][..],
        ),
    ]);
    let mut card = Card::new(&transcript);
    let profile = execute(&mut card, probe_device(Default::default())?)?;
    let mut operation = piv::batch(
        &profile,
        vec![
            BatchRequest::ReadObject(ObjectId::from_bytes(&[0x7e])?),
            BatchRequest::ReadCertificate(Slot::Authentication),
        ],
        Default::default(),
    )?;
    drop(profile);
    let error = drive(&mut card, &mut operation).expect_err("the fixture's certificate is absent");
    let progress = piv::batch_progress(&operation).ok_or("missing Batch progress")?;
    println!(
        "completed: {}; failed index: {:?}; error: {error}",
        progress.items().len(),
        progress.failed_index()
    );
    let Some(BatchItem::Bytes(data)) = progress.items().first() else {
        return Err("unexpected item".into());
    };
    assert_eq!(data.as_bytes(), &[0x42]);
    // Inspect/report partial results, then release memory. Never replay the Batch.
    drop(operation);
    card.finish()
}
