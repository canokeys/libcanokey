use canokey_protocol::tlv::{TlvLimits, TlvReader};
#[test]
fn explicit_ber_mode_accepts_fixed_width_lengths_without_weakening_default() {
    let bytes = [0x6e, 0x82, 0, 4, 0x73, 0x82, 0, 0];
    assert!(TlvReader::new(&bytes, TlvLimits::default()).next().is_err());
    let outer = TlvReader::new_ber(&bytes, TlvLimits::default())
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        outer.children().unwrap().next().unwrap().unwrap().value,
        &[]
    );
    for malformed in [
        &[0x6e, 0x80][..],
        &[0x6e, 0x82, 0, 1],
        &[0x6e, 0x85, 0, 0, 0, 0, 0],
    ] {
        assert!(TlvReader::new_ber(malformed, TlvLimits::default())
            .next()
            .is_err());
    }
}
