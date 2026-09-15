#[allow(dead_code)]
mod support;
use canokey_piv::*;
use canokey_protocol::{ErrorKind, OperationOptions, Step};
use support::*;
const POINT: &str = concat!(
    "04",
    "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
    "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
);
fn input(role: Sm2Role) -> Sm2AgreementInput {
    Sm2AgreementInput {
        role,
        peer_static: hex(POINT),
        peer_ephemeral: hex(POINT),
        user_id: None,
        peer_id: None,
        key_len: 16,
    }
}
fn public_reply() -> Vec<u8> {
    let mut r = hex("7c438241");
    r.extend(hex(POINT));
    r.extend([0x90, 0]);
    r
}
fn secret_reply(responder: bool) -> Vec<u8> {
    let mut r = if responder {
        let mut r = hex("7c558241");
        r.extend(hex(POINT));
        r.extend([0x85, 16]);
        r
    } else {
        hex("7c128210")
    };
    r.extend([0x42; 16]);
    r.extend([0x90, 0]);
    r
}
fn command() -> Vec<u8> {
    let mut c = hex("0087559d927c818f820085818a8641");
    c.extend(hex(POINT));
    c.extend([0x87, 65]);
    c.extend(hex(POINT));
    c.extend([0x89, 2, 0, 16]);
    c
}
#[test]
fn agreement_keeps_peer_inputs_and_owns_result_for_both_roles() {
    for role in [Sm2Role::Initiator, Sm2Role::Responder] {
        let p = profile("3.1.0");
        let mut op = agree_sm2(
            &p,
            Slot::KeyManagement,
            input(role),
            Access::None,
            Default::default(),
        )
        .unwrap();
        drop(p);
        selected(&mut op);
        if role == Sm2Role::Initiator {
            assert_eq!(op.command().unwrap().as_bytes(), hex("00f7009d00"));
            op.advance(&hex("010155020202019000")).unwrap();
            assert_eq!(op.command().unwrap().as_bytes(), hex("0087559d047c028200"));
            op.advance(&public_reply()).unwrap();
        }
        assert_eq!(op.command().unwrap().as_bytes(), command());
        assert_eq!(
            op.advance(&secret_reply(role == Sm2Role::Responder))
                .unwrap(),
            Step::Done
        );
        let result = op.take_result().unwrap();
        drop(op);
        assert_eq!(result.ephemeral_public, hex(POINT));
        assert_eq!(result.key.as_bytes(), [0x42; 16]);
    }
}
#[test]
fn initiator_rejects_pin_always_before_ephemeral_generation_and_never_retries() {
    for policy in [0, 3, 0xfa] {
        let mut op = agree_sm2(
            &profile("3.1.0"),
            Slot::KeyManagement,
            input(Sm2Role::Initiator),
            Access::None,
            Default::default(),
        )
        .unwrap();
        selected(&mut op);
        assert!(op.advance(&[2, 2, policy, 1, 0x90, 0]).is_err());
        assert!(op.command().is_err());
    }
    let mut op = agree_sm2(
        &profile("3.1.0"),
        Slot::KeyManagement,
        input(Sm2Role::Initiator),
        Access::None,
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    op.advance(&[2, 2, 2, 1, 0x90, 0]).unwrap();
    op.advance(&public_reply()).unwrap();
    assert!(op.advance(&[0x6c, 16]).is_err());
    assert!(op.command().is_err());
}
#[test]
fn malformed_points_ids_results_and_short_channels_fail() {
    let mut bad = input(Sm2Role::Responder);
    bad.peer_static[1] ^= 1;
    assert!(agree_sm2(
        &profile("3.1.0"),
        Slot::KeyManagement,
        bad,
        Access::None,
        Default::default()
    )
    .is_err());
    let mut bad = input(Sm2Role::Responder);
    bad.user_id = Some(vec![]);
    assert!(agree_sm2(
        &profile("3.1.0"),
        Slot::KeyManagement,
        bad,
        Access::None,
        Default::default()
    )
    .is_err());
    let mut opts = OperationOptions::default();
    opts.exchange.max_command_bytes = 100;
    assert_eq!(
        agree_sm2(
            &profile("3.1.0"),
            Slot::KeyManagement,
            input(Sm2Role::Responder),
            Access::None,
            opts
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::LimitExceeded
    );
    for response in [
        hex("7c128210000000000000000000000000000000009000"),
        hex("7c0082009000"),
    ] {
        let mut op = agree_sm2(
            &profile("3.1.0"),
            Slot::KeyManagement,
            input(Sm2Role::Responder),
            Access::None,
            Default::default(),
        )
        .unwrap();
        selected(&mut op);
        assert!(op.advance(&response).is_err());
    }
    let mut op = agree_sm2(
        &profile("3.1.0"),
        Slot::KeyManagement,
        input(Sm2Role::Initiator),
        Access::None,
        Default::default(),
    )
    .unwrap();
    selected(&mut op);
    op.advance(&[2, 2, 2, 1, 0x90, 0]).unwrap();
    op.cancel();
    assert!(op.command().is_err());
    assert!(agree_sm2(
        &profile("3.0.3"),
        Slot::KeyManagement,
        input(Sm2Role::Responder),
        Access::None,
        Default::default()
    )
    .is_err());
}

#[test]
fn firmware_two_octet_ber_lengths_preserve_full_128_byte_agreements() {
    for role in [Sm2Role::Initiator, Sm2Role::Responder] {
        let mut parameters = input(role);
        parameters.key_len = 128;
        let mut op = agree_sm2(
            &profile("3.1.0"),
            Slot::KeyManagement,
            parameters,
            Access::Existing,
            Default::default(),
        )
        .unwrap();
        op.start().unwrap();
        if role == Sm2Role::Initiator {
            op.advance(&hex("010155020202019000")).unwrap();
            op.advance(&public_reply()).unwrap();
        }
        let mut inner = Vec::new();
        if role == Sm2Role::Responder {
            inner.extend([0x82, 65]);
            inner.extend(hex(POINT));
        }
        inner.extend([
            if role == Sm2Role::Initiator {
                0x82
            } else {
                0x85
            },
            0x82,
            0,
            0x80,
        ]);
        inner.extend([0x5a; 128]);
        let mut response = vec![0x7c, 0x82, 0, inner.len() as u8];
        response.extend(inner);
        response.extend([0x90, 0]);
        assert_eq!(op.advance(&response).unwrap(), Step::Done);
        assert_eq!(op.take_result().unwrap().key.as_bytes(), &[0x5a; 128]);
    }
}
