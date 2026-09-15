use canokey_piv::{read_certificate, read_object, read_object_container, Access, ObjectId, Slot};
use canokey_protocol::{ErrorKind, OperationOptions, Phase, Step};

#[allow(dead_code)]
mod support;

#[test]
fn malformed_object_containers_report_parsing_after_exchange() {
    let profile = support::profile("3.1.0");
    for response in ["9000", "700030009000", "530053009000", "5382019000"] {
        for preserve_container in [false, true] {
            let id = ObjectId::from_bytes(&[0x5f, 0xff, 0]).unwrap();
            let factory = if preserve_container {
                read_object_container
            } else {
                read_object
            };
            let mut op =
                factory(&profile, id, Access::Existing, OperationOptions::default()).unwrap();
            assert_eq!(op.start().unwrap(), Step::Exchange);
            let error = op.advance(&support::hex(response)).unwrap_err();
            assert_eq!(error.kind, ErrorKind::InvalidResponse);
            assert_eq!(error.phase, Phase::Parsing);
            assert_eq!(
                op.advance(&[0x90, 0]).unwrap_err().kind,
                ErrorKind::OperationStateError
            );
        }
        let mut certificate = read_certificate(
            &profile,
            Slot::Authentication,
            Access::Existing,
            OperationOptions::default(),
        )
        .unwrap();
        certificate.start().unwrap();
        assert_eq!(
            certificate
                .advance(&support::hex(response))
                .unwrap_err()
                .phase,
            Phase::Parsing
        );
    }
}

#[test]
fn object_status_errors_keep_command_phase() {
    let profile = support::profile("3.1.0");
    for (sw, kind) in [
        ("6A88", ErrorKind::NotFound),
        ("6982", ErrorKind::SecurityStatusNotSatisfied),
    ] {
        let mut op = read_object(
            &profile,
            ObjectId::from_bytes(&[0x5f, 0xff, 0]).unwrap(),
            Access::Existing,
            OperationOptions::default(),
        )
        .unwrap();
        op.start().unwrap();
        let error = op.advance(&support::hex(sw)).unwrap_err();
        assert_eq!(error.kind, kind);
        assert_eq!(error.phase, Phase::Command);
    }
}
