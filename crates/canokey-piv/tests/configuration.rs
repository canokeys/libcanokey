#[allow(dead_code)]
mod support;
use canokey_compat::AlgorithmConfig;
use canokey_piv::*;
use canokey_protocol::{ErrorKind, Step};
use support::*;
fn config() -> AlgorithmConfig {
    AlgorithmConfig::parse(&hex("01e00516e15354555657")).unwrap()
}
fn dual() -> Access {
    let Access::Management(management) = access() else {
        unreachable!()
    };
    Access::PinAndManagement {
        pin: Pin::from_bytes(b"123456").unwrap(),
        management,
    }
}
#[test]
fn directory_length_is_not_ber_and_bad_entries_remain_observable() {
    let p = profile("3.1.0");
    let mut data = hex("0101010290");
    for slot in 0x82..=0x95 {
        data.extend([slot, 2, 0, 0, 0, 0]);
    }
    data.extend([
        0x9a, 1, 0x11, 2, 3, 2, 0x9a, 0x80, 0xfa, 0xff, 0xfe, 0xfd, 0xff, 0, 0, 0, 0, 0, 0x9d, 3,
        0xff, 0xff, 0xff, 0xff,
    ]);
    let parsed = MetadataDirectory::parse(&p, &data, 200).unwrap();
    let entries = parsed.entries().unwrap();
    assert_eq!(entries.len(), 24);
    assert!(entries[0].has_certificate());
    assert!(!entries[0].has_key());
    assert_eq!(entries[20].algorithm, Some(Algorithm::EccP256));
    assert_eq!(
        entries[21].issues,
        vec![
            DirectoryIssue::DuplicateSlot,
            DirectoryIssue::UnknownFlags,
            DirectoryIssue::KeyFieldsWithoutKey
        ]
    );
    assert_eq!(
        entries[22].issues,
        vec![DirectoryIssue::UnknownSlot, DirectoryIssue::EmptyFlags]
    );
    assert_eq!(entries[23].key_fields, [0xff; 4]);
    assert_eq!(entries[23].algorithm, None);
    let mut op = read_metadata_directory(&p, Access::None, Default::default()).unwrap();
    drop(p);
    selected(&mut op);
    assert_eq!(op.command().unwrap().as_bytes(), hex("00f7010000"));
    data.extend([0x90, 0]);
    assert_eq!(op.advance(&data).unwrap(), Step::Done);
    assert_eq!(op.result().unwrap().entries().unwrap().len(), 24);
    for data in [
        hex("0101010201ff"),
        hex("010101020600"),
        hex("010101020000"),
    ] {
        assert!(MetadataDirectory::parse(&profile("3.1.0"), &data, 200).is_err());
    }
    let opaque = hex("0101090203aabbcc");
    let d = MetadataDirectory::parse(&profile("3.1.0"), &opaque, 200).unwrap();
    assert_eq!(d.version(), 9);
    assert!(d.entries().is_none());
    assert_eq!(d.raw(), opaque);
}
#[test]
fn names_preserve_utf16_and_mutations_do_not_touch_certificates() {
    let name = ContainerName::from_text("Key 🔑").unwrap();
    assert_eq!(name.as_utf16le(), hex("4b006500790020003dd811dd"));
    let mut op = set_container_name(
        &profile("3.1.0"),
        Slot::Signature,
        name,
        access(),
        Default::default(),
    )
    .unwrap();
    authenticate(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("00f5019c0c4b006500790020003dd811dd")
    );
    op.advance(&[0x90, 0]).unwrap();
    let mut op = read_container_name(
        &profile("3.1.0"),
        Slot::Signature,
        Access::None,
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    assert_eq!(op.command().unwrap().as_bytes(), hex("00f5009c00"));
    op.advance(&hex("4b006500790020003dd811dd9000")).unwrap();
    assert_eq!(op.take_result().unwrap().text(), "Key 🔑");
    for bytes in [
        hex("00"),
        hex("0000"),
        hex("00d8"),
        hex("00dc"),
        vec![1; 80],
    ] {
        assert!(ContainerName::from_utf16le(&bytes).is_err());
    }
    for (mut op, cmd) in [
        (
            move_key(
                &profile("3.1.0"),
                Slot::Signature,
                Slot::KeyManagement,
                access(),
                Default::default(),
            )
            .unwrap(),
            hex("00f69d9c"),
        ),
        (
            delete_key(
                &profile("3.1.0"),
                Slot::Signature,
                access(),
                Default::default(),
            )
            .unwrap(),
            hex("00f6ff9c"),
        ),
        (
            set_container_name(
                &profile("3.1.0"),
                Slot::Signature,
                ContainerName::from_text("").unwrap(),
                access(),
                Default::default(),
            )
            .unwrap(),
            hex("00f5019c00"),
        ),
    ] {
        authenticate(&mut op);
        assert_eq!(op.command().unwrap().as_bytes(), cmd);
        op.advance(&[0x90, 0]).unwrap();
        assert!(op.command().is_err());
    }
    assert!(move_key(
        &profile("3.1.0"),
        Slot::Signature,
        Slot::Signature,
        access(),
        Default::default()
    )
    .is_err());
}
#[test]
fn retry_reset_is_dually_authenticated_and_config_changes_require_reprobe() {
    assert!(reset_pin_puk_retries(&profile("3.1.0"), 3, 5, access(), Default::default()).is_err());
    let mut op =
        reset_pin_puk_retries(&profile("3.1.0"), 3, 5, dual(), Default::default()).unwrap();
    authenticate(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("0020008008313233343536ffff")
    );
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(op.command().unwrap().as_bytes(), hex("00fa0305"));
    op.advance(&[0x90, 0]).unwrap();
    for (pin, puk) in [(0, 3), (16, 3), (3, 0), (3, 16)] {
        assert!(
            reset_pin_puk_retries(&profile("3.1.0"), pin, puk, dual(), Default::default()).is_err()
        );
    }
    let mut op =
        set_algorithm_config(&profile("3.1.0"), config(), access(), Default::default()).unwrap();
    authenticate(&mut op);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("00ee02000a01e00516e15354555657")
    );
    op.advance(&[0x90, 0]).unwrap();
    assert_eq!(
        op.result().unwrap().profile_effect,
        ProfileEffect::ReprobeRequired
    );
    let mut op = reset_piv(&profile("3.1.0"), Default::default()).unwrap();
    selected(&mut op);
    assert_eq!(op.command().unwrap().as_bytes(), hex("00fb0000"));
    assert_eq!(
        op.advance(&[0x69, 0x82]).unwrap_err().kind,
        ErrorKind::SecurityStatusNotSatisfied
    );
    assert!(op.command().is_err()); // Never manufacture PIN failures to enable reset.
    let mut op = attest(&profile("3.1.0"), Slot::Signature, true, Default::default()).unwrap();
    selected(&mut op);
    assert_eq!(op.command().unwrap().as_bytes(), hex("00f99c0000"));
    assert!(op.advance(&[0x6c, 0x40]).is_err());
    assert!(op.command().is_err());
}
#[test]
fn batch_authentication_and_profile_invalidation_are_explicit() {
    let p = profile("3.1.0");
    let requests = || {
        vec![
            BatchRequest::SetAlgorithmConfig(config()),
            BatchRequest::ReadAlgorithmConfig,
        ]
    };
    assert!(batch(&p, requests(), Default::default()).is_err());
    let Access::Management(auth) = access() else {
        unreachable!()
    };
    assert!(batch(
        &p,
        vec![
            BatchRequest::AuthenticateManagement(auth),
            BatchRequest::ResetPinPukRetries {
                pin_retries: 3,
                puk_retries: 3
            }
        ],
        Default::default()
    )
    .is_err());
    let Access::Management(auth) = access() else {
        unreachable!()
    };
    assert!(batch(
        &p,
        vec![
            BatchRequest::AuthenticateManagement(auth),
            BatchRequest::VerifyPin(Pin::from_bytes(b"123456").unwrap()),
            BatchRequest::ResetPinPukRetries {
                pin_retries: 3,
                puk_retries: 3
            },
            BatchRequest::DeleteKey(Slot::Signature)
        ],
        Default::default()
    )
    .is_err());
    let mut op = batch(
        &p,
        vec![
            BatchRequest::ReadMetadataDirectory,
            BatchRequest::ReadContainerName(Slot::Signature),
        ],
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    op.advance(&hex("01010102009000")).unwrap();
    assert!(op.advance(&hex("6a88")).is_err());
    assert!(
        matches!(&batch_progress(&op).unwrap().items()[0],BatchItem::Directory(d) if d.entries().unwrap().is_empty())
    );
    assert!(set_container_name(
        &p,
        Slot::Signature,
        ContainerName::from_text("x").unwrap(),
        Access::None,
        Default::default()
    )
    .is_err());
    assert!(delete_key(
        &profile("3.0.3"),
        Slot::Signature,
        access(),
        Default::default()
    )
    .is_err());
}

#[test]
fn selected_names_include_attestation_and_never_replay_writes() {
    let p = profile("3.1.0");
    let selected = (p).clone();
    assert_eq!(
        set_container_name(
            &selected,
            Slot::Signature,
            ContainerName::from_text("key").unwrap(),
            Access::None,
            Default::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidArgument
    );
    let management = (p).clone();
    let mut write = set_container_name(
        &management,
        ContainerNameReference::Attestation,
        ContainerName::from_text("K").unwrap(),
        Access::Existing,
        Default::default(),
    )
    .unwrap();
    let mut clear = set_container_name(
        &management,
        Slot::Signature,
        ContainerName::from_text("").unwrap(),
        Access::Existing,
        Default::default(),
    )
    .unwrap();
    let mut read = read_container_name(
        &selected,
        ContainerNameReference::Attestation,
        Access::Existing,
        Default::default(),
    )
    .unwrap();
    drop(p);
    drop(selected);
    drop(management);
    assert_eq!(write.start().unwrap(), Step::Exchange);
    assert_eq!(write.command().unwrap().as_bytes(), hex("00f501f9024b00"));
    assert_eq!(
        write.advance(&hex("019000")).unwrap_err().kind,
        ErrorKind::InvalidResponse
    );
    assert!(write.command().is_err());
    assert_eq!(clear.start().unwrap(), Step::Exchange);
    assert_eq!(clear.command().unwrap().as_bytes(), hex("00f5019c00"));
    assert!(clear.advance(&hex("6c10")).is_err());
    assert!(clear.command().is_err());
    assert_eq!(read.start().unwrap(), Step::Exchange);
    assert_eq!(read.command().unwrap().as_bytes(), hex("00f500f900"));
    let error = read.advance(&hex("6a88")).unwrap_err();
    assert_eq!(error.kind, ErrorKind::NotFound);
    assert!(read.result().is_err());
}
