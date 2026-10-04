// SPDX-License-Identifier: Apache-2.0
use canokey_compat::{
    Capability, CompatibilityWarning, DeviceObservations, DeviceProfile, Support,
};

#[test]
fn rust_release_keeps_identity_and_modern_capabilities() {
    for firmware in ["4.0.0", "4.0.0-dev+g12345678"] {
        let profile =
            DeviceProfile::from_observations(DeviceObservations::new(firmware.as_bytes().to_vec()))
                .unwrap();
        assert_eq!(profile.info().firmware_text(), firmware.as_bytes());
        assert!(!profile
            .warnings()
            .contains(&CompatibilityWarning::LatestKnownFallback));
        for feature in [
            Capability::Admin,
            Capability::AdminPublicConfiguration,
            Capability::OathModern,
            Capability::OathChallengeResponse,
            Capability::OpenPgpRetryReset,
            Capability::KeyMoveDelete,
            Capability::Attestation,
            Capability::CertificateDeletion,
        ] {
            assert_eq!(profile.capability(feature).support, Support::Supported);
        }
        assert_eq!(profile.piv_slot_support(0x95).support, Support::Supported);
        assert!(profile.sm2_uses_p1363_signatures());
        assert!(!profile.legacy_explicit_le());
    }
}

#[test]
fn nearby_unaudited_releases_remain_unknown() {
    for firmware in ["3.2.0", "4.0.1", "4.1.0", "5.0.0"] {
        let profile =
            DeviceProfile::from_observations(DeviceObservations::new(firmware.as_bytes().to_vec()))
                .unwrap();
        assert_eq!(
            profile.capability(Capability::Admin).support,
            Support::Unknown
        );
    }
}
