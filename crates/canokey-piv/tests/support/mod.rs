use canokey_compat::{AlgorithmConfig, DeviceObservations, DeviceProfile, PivApplicationVersion};
use canokey_piv::{Access, ManagementAuthentication, ManagementKey, ManagementKeyAlgorithm};
use canokey_protocol::{Operation, Step};
pub fn profile(version: &str) -> DeviceProfile {
    let mut o = DeviceObservations::new(version.as_bytes().to_vec());
    o.piv_version = Some(PivApplicationVersion([5, 7, 0]));
    o.algorithm_config = Some(
        AlgorithmConfig::parse(&[1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x54, 0x55, 0x56, 0x57]).unwrap(),
    );
    DeviceProfile::from_observations(o).unwrap()
}
pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
pub fn access() -> Access {
    Access::Management(ManagementAuthentication::external(
        ManagementKey::from_bytes(ManagementKeyAlgorithm::Aes192, &(0..24).collect::<Vec<_>>())
            .unwrap(),
    ))
}
pub fn selected<T>(op: &mut Operation<T>) {
    selected_with_le(op, false);
}
pub fn selected_with_le<T>(op: &mut Operation<T>, explicit_le: bool) {
    assert_eq!(op.start().unwrap(), Step::Exchange);
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex(if explicit_le {
            "00a4040005a00000030800"
        } else {
            "00a4040005a000000308"
        })
    );
    op.advance(&[0x90, 0]).unwrap();
}
pub fn authenticate<T>(op: &mut Operation<T>) {
    selected(op);
    assert_eq!(op.command().unwrap().as_bytes(), hex("00870a9b047c028100"));
    op.advance(&hex("7c12811000112233445566778899aabbccddeeff9000"))
        .unwrap();
    assert_eq!(
        op.command().unwrap().as_bytes(),
        hex("00870a9b147c128210dda97ca4864cdfe06eaf70a0ec0d7191")
    );
    op.advance(&[0x90, 0]).unwrap();
}
pub const P256_POINT:&str="046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
