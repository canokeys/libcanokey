// SPDX-License-Identifier: Apache-2.0
use canokey_compat::{
    Algorithm, Capability, CompatibilityWarning, DeviceObservations, DeviceProfile,
    ManagementKeyAlgorithm, Support,
};

#[test]
fn audited_modern_releases_keep_identity_and_capabilities() {
    for firmware in [
        "3.1.1",
        "3.1.1-dev+g12345678",
        "4.0.0",
        "4.0.0-dev+g12345678",
    ] {
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
        assert!(profile.admin_configuration_layout().is_ok());
        for status in [
            profile.management_key_support(ManagementKeyAlgorithm::Aes192),
            profile.algorithm_config_read_support(),
            profile.openpgp_algorithm_support(Algorithm::EccP521, true),
        ] {
            assert_eq!(status.support, Support::Supported);
        }
        assert_eq!(
            profile.key_algorithm_support(Algorithm::MlDsa65).support,
            Support::Unknown
        );
    }
}

#[test]
fn nearby_unaudited_releases_remain_unknown() {
    for firmware in ["3.1.2", "3.1.2-dev", "3.2.0", "4.0.1", "4.1.0", "5.0.0"] {
        let profile =
            DeviceProfile::from_observations(DeviceObservations::new(firmware.as_bytes().to_vec()))
                .unwrap();
        assert_eq!(
            profile.capability(Capability::Admin).support,
            Support::Unknown
        );
        assert!(profile
            .warnings()
            .contains(&CompatibilityWarning::LatestKnownFallback));
        assert!(profile.admin_configuration_layout().is_err());
        assert_eq!(
            profile
                .management_key_support(ManagementKeyAlgorithm::Aes192)
                .support,
            Support::Unknown
        );
    }
}
