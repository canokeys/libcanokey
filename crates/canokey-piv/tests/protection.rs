use canokey_piv::{protected_management_key_from_object, ManagementProtection};
use canokey_protocol::{ErrorKind, Phase};
fn wrap(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, data.len() as u8];
    out.extend(data);
    out
}
#[test]
fn absent_policy_is_distinct_from_malformed_or_partly_configured_policy() {
    for data in [vec![0x53, 0], vec![0x53, 2, 0x80, 0]] {
        let policy = ManagementProtection::from_admin_object(&data).unwrap();
        assert_eq!(policy.flags(), 0);
        assert!(!policy.protects_management_key());
    }
    for flags in [0, 1, 2, 3, 0x83] {
        let object = wrap(0x53, &wrap(0x80, &[0x81, 1, flags]));
        let policy = ManagementProtection::from_admin_object(&object).unwrap();
        assert_eq!(policy.flags(), flags);
        assert_eq!(policy.claims_blocked_puk(), flags & 1 != 0);
        assert_eq!(policy.protects_management_key(), flags & 2 != 0);
    }
    for fields in [
        vec![0x81, 0],
        vec![0x81, 1, 0, 0x81, 1, 3],
        vec![0x84, 0],
        vec![0x82, 0],
        vec![0x83, 0],
        vec![0x82, 0, 0x83, 0],
        [vec![0x82, 16], vec![0; 16]].concat(),
        vec![0x82, 1, 0],
        vec![0x83, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        let error =
            ManagementProtection::from_admin_object(&wrap(0x53, &wrap(0x80, &fields))).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidResponse);
        assert_eq!(error.phase, Phase::Parsing);
    }
    let with_optional_fields = wrap(0x53, &wrap(0x80, &[0x81, 1, 3, 0x82, 0, 0x83, 0]));
    assert_eq!(
        ManagementProtection::from_admin_object(&with_optional_fields)
            .unwrap()
            .flags(),
        3
    );
    for data in [
        vec![],
        vec![0x53, 1],
        vec![0x53, 0, 0x53, 0],
        vec![0x53, 2, 0x80, 1],
    ] {
        assert!(ManagementProtection::from_admin_object(&data).is_err());
    }
    assert_eq!(
        ManagementProtection::from_admin_object(&[0; 129])
            .unwrap_err()
            .kind,
        ErrorKind::LimitExceeded
    );
}
#[test]
fn protected_key_requires_exact_nesting_and_is_owned() {
    let key: Vec<u8> = (0..24).collect();
    let mut data = wrap(0x53, &wrap(0x88, &wrap(0x89, &key)));
    let parsed = protected_management_key_from_object(&data).unwrap();
    data.fill(0);
    assert_eq!(parsed.as_bytes(), key);
    for length in [0, 23, 25] {
        assert!(protected_management_key_from_object(&wrap(
            0x53,
            &wrap(0x88, &wrap(0x89, &vec![0; length]))
        ))
        .is_err());
    }
    let mut duplicate = wrap(0x89, &key);
    duplicate.extend(wrap(0x89, &key));
    assert!(protected_management_key_from_object(&wrap(0x53, &wrap(0x88, &duplicate))).is_err());
    let mut trailing = wrap(0x53, &wrap(0x88, &wrap(0x89, &key)));
    trailing.push(0);
    assert!(protected_management_key_from_object(&trailing).is_err());
    assert_eq!(
        protected_management_key_from_object(&[0; 65])
            .unwrap_err()
            .kind,
        ErrorKind::LimitExceeded
    );
}
