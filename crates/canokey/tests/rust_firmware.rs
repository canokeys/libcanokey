// SPDX-License-Identifier: Apache-2.0
use canokey_compat::{
    Algorithm, AlgorithmConfig, Capability, CompatibilityWarning, DeviceObservations,
    DeviceProfile, Evidence, FirmwareVersion, ManagementKeyAlgorithm, Support,
};

#[test]
fn compatible_patch_releases_keep_identity_and_series_rules() {
    for firmware in [
        "3.1.0",
        "3.1.1",
        "3.1.2",
        "3.1.2+build",
        "3.1.42-dev+g12345678",
        "3.1.65535",
        "4.0.0",
        "4.0.1",
        "4.0.42-dev+g12345678",
        "4.0.65535",
    ] {
        let profile =
            DeviceProfile::from_observations(DeviceObservations::new(firmware.as_bytes().to_vec()))
                .unwrap();
        assert_eq!(profile.info().firmware_text(), firmware.as_bytes());
        let version = FirmwareVersion::parse(firmware).unwrap();
        assert_eq!(profile.info().firmware(), Some(&version));
        assert_eq!(
            profile
                .warnings()
                .contains(&CompatibilityWarning::DeclaredBaseVersion),
            version.suffix.is_some()
        );
        assert!(!profile
            .warnings()
            .contains(&CompatibilityWarning::LatestKnownFallback));
        for feature in [
            Capability::Admin,
            Capability::Metadata,
            Capability::EccP384,
            Capability::AdminPublicConfiguration,
            Capability::OathModern,
            Capability::OathChallengeResponse,
            Capability::OpenPgpRetryReset,
            Capability::KeyMoveDelete,
            Capability::Attestation,
            Capability::CertificateDeletion,
        ] {
            assert_eq!(profile.capability(feature).support, Support::Supported);
            assert_eq!(
                profile.capability(feature).evidence,
                Evidence::FirmwareMatrix
            );
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
fn unknown_series_remain_restricted() {
    for firmware in ["3.2.0", "3.2.1-dev", "4.1.0", "4.1.42", "5.0.0"] {
        let profile =
            DeviceProfile::from_observations(DeviceObservations::new(firmware.as_bytes().to_vec()))
                .unwrap();
        assert_eq!(
            profile.capability(Capability::Admin).support,
            Support::Unknown
        );
        assert!(!profile.sm2_uses_p1363_signatures());
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

#[test]
fn observed_extension_ids_require_a_known_series() {
    for (firmware, expected) in [
        ("3.1.2", Support::Supported),
        ("4.0.7", Support::Supported),
        ("3.2.0", Support::Unknown),
        ("4.1.0", Support::Unknown),
    ] {
        let mut observations = DeviceObservations::new(firmware.as_bytes().to_vec());
        observations.algorithm_config = Some(
            AlgorithmConfig::parse(&[1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x15, 0x54, 0xe2, 0xe3])
                .unwrap(),
        );
        let profile = DeviceProfile::from_observations(observations).unwrap();
        assert_eq!(
            profile.key_algorithm_support(Algorithm::MlDsa65).support,
            expected
        );
        assert_eq!(
            profile.streaming_signing_support(Algorithm::Sm2).support,
            expected
        );
    }
}
