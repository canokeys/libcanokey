//! CTAP status codes (CTAP1_ERR/CTAP2_ERR) and their error classification.
//!
//! Every successful CTAP exchange returns a response whose first byte is a
//! CTAP status code. This module types that byte and classifies failures into
//! [`canokey_protocol`] errors. Note the crate-wide convention: for CTAP-level
//! failures [`Error::application_status`] carries the raw CTAP status byte,
//! while [`Error::status_word`] is reserved for ISO 7816 status words.

use canokey_protocol::{Error, ErrorKind, Phase};

/// One-byte CTAP status from the start of a successful CTAP response.
///
/// Typed interpretation is available through [`Self::code`]; the raw byte is
/// always available through [`Self::raw`]. Codes outside the CTAP1/CTAP2
/// table are retained raw and never rejected here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtapStatus(u8);
impl CtapStatus {
    /// CTAP1_ERR_SUCCESS (0x00).
    pub const SUCCESS: Self = Self(0x00);
    /// Return whether this status is CTAP1_ERR_SUCCESS.
    pub fn is_success(self) -> bool {
        self == Self::SUCCESS
    }
    /// Wrap a raw status byte received from the authenticator. The byte is
    /// retained as-is, including codes outside the CTAP status table.
    pub const fn from_raw(byte: u8) -> Self {
        Self(byte)
    }
    /// Return the raw status byte as sent by the authenticator.
    pub fn raw(self) -> u8 {
        self.0
    }
    /// Interpret this status as a typed CTAP error code.
    ///
    /// Returns `None` for bytes not present in the CTAP1/CTAP2 status table
    /// (for example 0x07..=0x09, 0x41..=0x7E, or the boundary 0xDF). The
    /// extension (0xE0..=0xEF) and vendor (0xF0..=0xFF) ranges are part of
    /// the table and map to [`CtapErrorCode::Extension`] /
    /// [`CtapErrorCode::Vendor`].
    pub fn code(self) -> Option<CtapErrorCode> {
        CtapErrorCode::from_byte(self.0)
    }
    /// Classify a non-success status into a protocol error, preserving the
    /// raw CTAP status byte in [`Error::application_status`]; the ISO 7816
    /// [`Error::status_word`] remains unset.
    pub(crate) fn into_error(self, phase: Phase) -> Option<Error> {
        if self.is_success() {
            return None;
        }
        let kind = match self.0 {
            // CTAP2_ERR_PIN_INVALID / CTAP2_ERR_PIN_POLICY_VIOLATION
            0x31 | 0x37 => ErrorKind::InvalidPin,
            // CTAP2_ERR_PIN_BLOCKED / CTAP2_ERR_PIN_AUTH_BLOCKED
            0x32 | 0x34 => ErrorKind::PinBlocked,
            // CTAP2_ERR_PIN_AUTH_INVALID
            0x33 => ErrorKind::AuthenticationFailed,
            // CTAP2_ERR_PIN_NOT_SET / CTAP2_ERR_PUAT_REQUIRED
            0x35 | 0x36 => ErrorKind::SecurityStatusNotSatisfied,
            // CTAP2_ERR_NO_CREDENTIALS / CTAP2_ERR_INVALID_CREDENTIAL
            0x2e | 0x22 => ErrorKind::NotFound,
            // CREDENTIAL_EXCLUDED / OPERATION_DENIED / KEEPALIVE_CANCEL /
            // USER_ACTION_TIMEOUT / NOT_ALLOWED / UP_REQUIRED
            0x19 | 0x27 | 0x2d | 0x2f | 0x30 | 0x3b => ErrorKind::ConditionsNotSatisfied,
            // CTAP2_ERR_UNSUPPORTED_ALGORITHM
            0x26 => ErrorKind::UnsupportedAlgorithm,
            // CTAP2_ERR_UNSUPPORTED_OPTION / CTAP2_ERR_INVALID_OPTION
            0x2b | 0x2c => ErrorKind::UnsupportedFeature,
            // LIMIT_EXCEEDED / LARGE_BLOB_STORAGE_FULL / KEY_STORE_FULL /
            // REQUEST_TOO_LARGE
            0x15 | 0x18 | 0x28 | 0x39 => ErrorKind::LimitExceeded,
            // CBOR_UNEXPECTED_TYPE / INVALID_CBOR / MISSING_PARAMETER
            0x11 | 0x12 | 0x14 => ErrorKind::ProtocolViolation,
            _ => ErrorKind::UnexpectedStatusWord,
        };
        let mut error = Error::new(kind).at(phase);
        error.application_status = Some(self.0);
        Some(error)
    }
}

/// A typed CTAP1/CTAP2 status code.
///
/// The extension and vendor ranges keep their low nibble so every code in
/// the table round-trips losslessly through [`Self::byte`]. Bytes not listed
/// in the CTAP specification are not representable; see
/// [`CtapErrorCode::from_byte`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtapErrorCode {
    /// CTAP1_ERR_SUCCESS (0x00).
    Ctap1ErrSuccess,
    /// CTAP1_ERR_INVALID_COMMAND (0x01).
    Ctap1ErrInvalidCommand,
    /// CTAP1_ERR_INVALID_PARAMETER (0x02).
    Ctap1ErrInvalidParameter,
    /// CTAP1_ERR_INVALID_LENGTH (0x03).
    Ctap1ErrInvalidLength,
    /// CTAP1_ERR_INVALID_SEQ (0x04).
    Ctap1ErrInvalidSeq,
    /// CTAP1_ERR_TIMEOUT (0x05).
    Ctap1ErrTimeout,
    /// CTAP1_ERR_CHANNEL_BUSY (0x06).
    Ctap1ErrChannelBusy,
    /// CTAP1_ERR_LOCK_REQUIRED (0x0A).
    Ctap1ErrLockRequired,
    /// CTAP1_ERR_INVALID_CHANNEL (0x0B).
    Ctap1ErrInvalidChannel,
    /// CTAP2_ERR_CBOR_UNEXPECTED_TYPE (0x11).
    Ctap2ErrCborUnexpectedType,
    /// CTAP2_ERR_INVALID_CBOR (0x12).
    Ctap2ErrInvalidCbor,
    /// CTAP2_ERR_MISSING_PARAMETER (0x14).
    Ctap2ErrMissingParameter,
    /// CTAP2_ERR_LIMIT_EXCEEDED (0x15).
    Ctap2ErrLimitExceeded,
    /// CTAP2_ERR_FP_DATABASE_FULL (0x17).
    Ctap2ErrFpDatabaseFull,
    /// CTAP2_ERR_LARGE_BLOB_STORAGE_FULL (0x18).
    Ctap2ErrLargeBlobStorageFull,
    /// CTAP2_ERR_CREDENTIAL_EXCLUDED (0x19).
    Ctap2ErrCredentialExcluded,
    /// CTAP2_ERR_PROCESSING (0x21).
    Ctap2ErrProcessing,
    /// CTAP2_ERR_INVALID_CREDENTIAL (0x22).
    Ctap2ErrInvalidCredential,
    /// CTAP2_ERR_USER_ACTION_PENDING (0x23).
    Ctap2ErrUserActionPending,
    /// CTAP2_ERR_OPERATION_PENDING (0x24).
    Ctap2ErrOperationPending,
    /// CTAP2_ERR_NO_OPERATIONS (0x25).
    Ctap2ErrNoOperations,
    /// CTAP2_ERR_UNSUPPORTED_ALGORITHM (0x26).
    Ctap2ErrUnsupportedAlgorithm,
    /// CTAP2_ERR_OPERATION_DENIED (0x27).
    Ctap2ErrOperationDenied,
    /// CTAP2_ERR_KEY_STORE_FULL (0x28).
    Ctap2ErrKeyStoreFull,
    /// CTAP2_ERR_UNSUPPORTED_OPTION (0x2B).
    Ctap2ErrUnsupportedOption,
    /// CTAP2_ERR_INVALID_OPTION (0x2C).
    Ctap2ErrInvalidOption,
    /// CTAP2_ERR_KEEPALIVE_CANCEL (0x2D).
    Ctap2ErrKeepaliveCancel,
    /// CTAP2_ERR_NO_CREDENTIALS (0x2E).
    Ctap2ErrNoCredentials,
    /// CTAP2_ERR_USER_ACTION_TIMEOUT (0x2F).
    Ctap2ErrUserActionTimeout,
    /// CTAP2_ERR_NOT_ALLOWED (0x30).
    Ctap2ErrNotAllowed,
    /// CTAP2_ERR_PIN_INVALID (0x31).
    Ctap2ErrPinInvalid,
    /// CTAP2_ERR_PIN_BLOCKED (0x32).
    Ctap2ErrPinBlocked,
    /// CTAP2_ERR_PIN_AUTH_INVALID (0x33).
    Ctap2ErrPinAuthInvalid,
    /// CTAP2_ERR_PIN_AUTH_BLOCKED (0x34).
    Ctap2ErrPinAuthBlocked,
    /// CTAP2_ERR_PIN_NOT_SET (0x35).
    Ctap2ErrPinNotSet,
    /// CTAP2_ERR_PUAT_REQUIRED (0x36).
    Ctap2ErrPuatRequired,
    /// CTAP2_ERR_PIN_POLICY_VIOLATION (0x37).
    Ctap2ErrPinPolicyViolation,
    /// CTAP2_ERR_RESERVED (0x38).
    Ctap2ErrReserved,
    /// CTAP2_ERR_REQUEST_TOO_LARGE (0x39).
    Ctap2ErrRequestTooLarge,
    /// CTAP2_ERR_ACTION_TIMEOUT (0x3A).
    Ctap2ErrActionTimeout,
    /// CTAP2_ERR_UP_REQUIRED (0x3B).
    Ctap2ErrUpRequired,
    /// CTAP2_ERR_UV_BLOCKED (0x3C).
    Ctap2ErrUvBlocked,
    /// CTAP2_ERR_INTEGRITY_FAILURE (0x3D).
    Ctap2ErrIntegrityFailure,
    /// CTAP2_ERR_INVALID_SUBCOMMAND (0x3E).
    Ctap2ErrInvalidSubcommand,
    /// CTAP2_ERR_UV_INVALID (0x3F).
    Ctap2ErrUvInvalid,
    /// CTAP2_ERR_UNAUTHORIZED_PERMISSION (0x40).
    Ctap2ErrUnauthorizedPermission,
    /// CTAP1_ERR_OTHER (0x7F).
    Ctap1ErrOther,
    /// CTAP2_ERR_EXTENSION_00..=0F (0xE0..=0xEF); holds the low nibble 0..=15.
    Extension(u8),
    /// CTAP2_ERR_VENDOR_00..=0F (0xF0..=0xFF); holds the low nibble 0..=15.
    Vendor(u8),
}
impl CtapErrorCode {
    /// Last status byte reserved by the CTAP specification (0xDF); never a
    /// valid code itself, like all bytes between the table and the ranges.
    pub const SPEC_LAST: u8 = 0xdf;
    /// First byte of the extension range (0xE0).
    pub const EXTENSION_FIRST: u8 = 0xe0;
    /// Last byte of the extension range (0xEF).
    pub const EXTENSION_LAST: u8 = 0xef;
    /// First byte of the vendor range (0xF0).
    pub const VENDOR_FIRST: u8 = 0xf0;
    /// Last byte of the vendor range (0xFF).
    pub const VENDOR_LAST: u8 = 0xff;

    /// Map a raw status byte to a typed code, or `None` when the byte is not
    /// part of the CTAP status table.
    pub fn from_byte(byte: u8) -> Option<Self> {
        let code = match byte {
            0x00 => Self::Ctap1ErrSuccess,
            0x01 => Self::Ctap1ErrInvalidCommand,
            0x02 => Self::Ctap1ErrInvalidParameter,
            0x03 => Self::Ctap1ErrInvalidLength,
            0x04 => Self::Ctap1ErrInvalidSeq,
            0x05 => Self::Ctap1ErrTimeout,
            0x06 => Self::Ctap1ErrChannelBusy,
            0x0a => Self::Ctap1ErrLockRequired,
            0x0b => Self::Ctap1ErrInvalidChannel,
            0x11 => Self::Ctap2ErrCborUnexpectedType,
            0x12 => Self::Ctap2ErrInvalidCbor,
            0x14 => Self::Ctap2ErrMissingParameter,
            0x15 => Self::Ctap2ErrLimitExceeded,
            0x17 => Self::Ctap2ErrFpDatabaseFull,
            0x18 => Self::Ctap2ErrLargeBlobStorageFull,
            0x19 => Self::Ctap2ErrCredentialExcluded,
            0x21 => Self::Ctap2ErrProcessing,
            0x22 => Self::Ctap2ErrInvalidCredential,
            0x23 => Self::Ctap2ErrUserActionPending,
            0x24 => Self::Ctap2ErrOperationPending,
            0x25 => Self::Ctap2ErrNoOperations,
            0x26 => Self::Ctap2ErrUnsupportedAlgorithm,
            0x27 => Self::Ctap2ErrOperationDenied,
            0x28 => Self::Ctap2ErrKeyStoreFull,
            0x2b => Self::Ctap2ErrUnsupportedOption,
            0x2c => Self::Ctap2ErrInvalidOption,
            0x2d => Self::Ctap2ErrKeepaliveCancel,
            0x2e => Self::Ctap2ErrNoCredentials,
            0x2f => Self::Ctap2ErrUserActionTimeout,
            0x30 => Self::Ctap2ErrNotAllowed,
            0x31 => Self::Ctap2ErrPinInvalid,
            0x32 => Self::Ctap2ErrPinBlocked,
            0x33 => Self::Ctap2ErrPinAuthInvalid,
            0x34 => Self::Ctap2ErrPinAuthBlocked,
            0x35 => Self::Ctap2ErrPinNotSet,
            0x36 => Self::Ctap2ErrPuatRequired,
            0x37 => Self::Ctap2ErrPinPolicyViolation,
            0x38 => Self::Ctap2ErrReserved,
            0x39 => Self::Ctap2ErrRequestTooLarge,
            0x3a => Self::Ctap2ErrActionTimeout,
            0x3b => Self::Ctap2ErrUpRequired,
            0x3c => Self::Ctap2ErrUvBlocked,
            0x3d => Self::Ctap2ErrIntegrityFailure,
            0x3e => Self::Ctap2ErrInvalidSubcommand,
            0x3f => Self::Ctap2ErrUvInvalid,
            0x40 => Self::Ctap2ErrUnauthorizedPermission,
            0x7f => Self::Ctap1ErrOther,
            b @ Self::EXTENSION_FIRST..=Self::EXTENSION_LAST => Self::Extension(b & 0x0f),
            b @ Self::VENDOR_FIRST..=Self::VENDOR_LAST => Self::Vendor(b & 0x0f),
            _ => return None,
        };
        Some(code)
    }
    /// Return the raw status byte for this code; the exact inverse of
    /// [`Self::from_byte`] for every representable code.
    pub fn byte(self) -> u8 {
        match self {
            Self::Ctap1ErrSuccess => 0x00,
            Self::Ctap1ErrInvalidCommand => 0x01,
            Self::Ctap1ErrInvalidParameter => 0x02,
            Self::Ctap1ErrInvalidLength => 0x03,
            Self::Ctap1ErrInvalidSeq => 0x04,
            Self::Ctap1ErrTimeout => 0x05,
            Self::Ctap1ErrChannelBusy => 0x06,
            Self::Ctap1ErrLockRequired => 0x0a,
            Self::Ctap1ErrInvalidChannel => 0x0b,
            Self::Ctap2ErrCborUnexpectedType => 0x11,
            Self::Ctap2ErrInvalidCbor => 0x12,
            Self::Ctap2ErrMissingParameter => 0x14,
            Self::Ctap2ErrLimitExceeded => 0x15,
            Self::Ctap2ErrFpDatabaseFull => 0x17,
            Self::Ctap2ErrLargeBlobStorageFull => 0x18,
            Self::Ctap2ErrCredentialExcluded => 0x19,
            Self::Ctap2ErrProcessing => 0x21,
            Self::Ctap2ErrInvalidCredential => 0x22,
            Self::Ctap2ErrUserActionPending => 0x23,
            Self::Ctap2ErrOperationPending => 0x24,
            Self::Ctap2ErrNoOperations => 0x25,
            Self::Ctap2ErrUnsupportedAlgorithm => 0x26,
            Self::Ctap2ErrOperationDenied => 0x27,
            Self::Ctap2ErrKeyStoreFull => 0x28,
            Self::Ctap2ErrUnsupportedOption => 0x2b,
            Self::Ctap2ErrInvalidOption => 0x2c,
            Self::Ctap2ErrKeepaliveCancel => 0x2d,
            Self::Ctap2ErrNoCredentials => 0x2e,
            Self::Ctap2ErrUserActionTimeout => 0x2f,
            Self::Ctap2ErrNotAllowed => 0x30,
            Self::Ctap2ErrPinInvalid => 0x31,
            Self::Ctap2ErrPinBlocked => 0x32,
            Self::Ctap2ErrPinAuthInvalid => 0x33,
            Self::Ctap2ErrPinAuthBlocked => 0x34,
            Self::Ctap2ErrPinNotSet => 0x35,
            Self::Ctap2ErrPuatRequired => 0x36,
            Self::Ctap2ErrPinPolicyViolation => 0x37,
            Self::Ctap2ErrReserved => 0x38,
            Self::Ctap2ErrRequestTooLarge => 0x39,
            Self::Ctap2ErrActionTimeout => 0x3a,
            Self::Ctap2ErrUpRequired => 0x3b,
            Self::Ctap2ErrUvBlocked => 0x3c,
            Self::Ctap2ErrIntegrityFailure => 0x3d,
            Self::Ctap2ErrInvalidSubcommand => 0x3e,
            Self::Ctap2ErrUvInvalid => 0x3f,
            Self::Ctap2ErrUnauthorizedPermission => 0x40,
            Self::Ctap1ErrOther => 0x7f,
            Self::Extension(low) => Self::EXTENSION_FIRST | (low & 0x0f),
            Self::Vendor(low) => Self::VENDOR_FIRST | (low & 0x0f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canokey_protocol::ErrorKind;
    #[test]
    fn error_classification_and_raw_byte_retention() {
        assert!(CtapStatus::SUCCESS.into_error(Phase::Command).is_none());
        let cases: &[(u8, ErrorKind)] = &[
            (0x31, ErrorKind::InvalidPin),
            (0x37, ErrorKind::InvalidPin),
            (0x32, ErrorKind::PinBlocked),
            (0x34, ErrorKind::PinBlocked),
            (0x33, ErrorKind::AuthenticationFailed),
            (0x35, ErrorKind::SecurityStatusNotSatisfied),
            (0x36, ErrorKind::SecurityStatusNotSatisfied),
            (0x2e, ErrorKind::NotFound),
            (0x22, ErrorKind::NotFound),
            (0x19, ErrorKind::ConditionsNotSatisfied),
            (0x27, ErrorKind::ConditionsNotSatisfied),
            (0x2d, ErrorKind::ConditionsNotSatisfied),
            (0x2f, ErrorKind::ConditionsNotSatisfied),
            (0x30, ErrorKind::ConditionsNotSatisfied),
            (0x3b, ErrorKind::ConditionsNotSatisfied),
            (0x26, ErrorKind::UnsupportedAlgorithm),
            (0x2b, ErrorKind::UnsupportedFeature),
            (0x2c, ErrorKind::UnsupportedFeature),
            (0x15, ErrorKind::LimitExceeded),
            (0x18, ErrorKind::LimitExceeded),
            (0x28, ErrorKind::LimitExceeded),
            (0x39, ErrorKind::LimitExceeded),
            (0x11, ErrorKind::ProtocolViolation),
            (0x12, ErrorKind::ProtocolViolation),
            (0x14, ErrorKind::ProtocolViolation),
            (0x01, ErrorKind::UnexpectedStatusWord),
            (0x21, ErrorKind::UnexpectedStatusWord),
            (0x7f, ErrorKind::UnexpectedStatusWord),
            (0xe0, ErrorKind::UnexpectedStatusWord),
            (0xff, ErrorKind::UnexpectedStatusWord),
            (0x41, ErrorKind::UnexpectedStatusWord),
        ];
        for &(byte, kind) in cases {
            let error = CtapStatus(byte)
                .into_error(Phase::Command)
                .expect("non-success status must classify");
            assert_eq!(error.kind, kind, "byte {byte:#04x}");
            assert_eq!(error.phase, Phase::Command);
            // CTAP-level failures carry the raw CTAP status byte here.
            assert_eq!(error.application_status, Some(byte));
            assert_eq!(error.status_word, None);
        }
    }
}
