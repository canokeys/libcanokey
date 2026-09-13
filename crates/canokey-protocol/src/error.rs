//! Structured protocol failures, independent of transport and binding errors.
use crate::StatusWord;
/// Stable semantic categories for protocol failures. Transport errors stay outside
/// the core; callers must allow future variants of this non-exhaustive enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A caller value or options combination is invalid.
    InvalidArgument,
    /// PIN/PUK bytes violate applet input rules.
    InvalidPin,
    /// Response framing or semantic content is malformed.
    InvalidResponse,
    /// The exchange sequence violates its conversation rules.
    ProtocolViolation,
    /// A frame, input, response, nesting, or exchange budget was exceeded.
    LimitExceeded,
    /// Explicit credential verification failed; retry information may be present.
    AuthenticationFailed,
    /// The card's mutual-authentication cryptogram did not match the host challenge.
    DeviceAuthenticationFailed,
    /// A credential reference is blocked.
    PinBlocked,
    /// Required authentication/security state is absent.
    SecurityStatusNotSatisfied,
    /// The card reports unmet execution conditions.
    ConditionsNotSatisfied,
    /// A requested applet object/reference was not found.
    NotFound,
    /// The required applet/device could not be selected.
    UnsupportedDevice,
    /// A capability or instruction is known to be unavailable.
    UnsupportedFeature,
    /// The requested algorithm cannot be used for this operation.
    UnsupportedAlgorithm,
    /// Available evidence cannot establish required capability support.
    CapabilityUnknown,
    /// An observed format/version is not understood (including certificate encoding).
    UnsupportedProtocolVersion,
    /// An unmapped status word was returned; inspect `Error::status_word`.
    UnexpectedStatusWord,
    /// A local lifecycle method was called in an invalid state.
    OperationStateError,
}
/// Context in which a protocol error was classified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Input/configuration validation or an error without a more specific phase.
    Construction,
    /// Applet selection.
    Select,
    /// Target applet command.
    Command,
    /// Credential verification or authentication exchange.
    Authentication,
    /// Response or structured-byte decoding.
    Parsing,
    /// Physical continuation, correction, or segmentation.
    Conversation,
}
/// Credential involved in an authentication error; never contains its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretReference {
    /// PIV user PIN.
    Pin,
    /// PIV PIN unblocking key.
    Puk,
    /// PIV management key.
    ManagementKey,
    /// Admin applet PIN.
    AdminPin,
    /// OATH access-code key, distinct from a PIN retry counter.
    OathAccess,
}
/// Owned, cloneable protocol failure with no secret payload.
/// Display is diagnostic English; applications own localization and transport errors.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{kind:?} during {phase:?}")]
pub struct Error {
    /// Semantic failure category.
    pub kind: ErrorKind,
    /// Command/parser context used to classify the error.
    pub phase: Phase,
    /// Original status when the failure came from a card status word.
    pub status_word: Option<StatusWord>,
    /// Credential reference when known; absent for non-authentication failures.
    pub reference: Option<SecretReference>,
    /// Retry count from an authentication 63Cx status; absent when not reported.
    pub retries_remaining: Option<u8>,
}
impl Error {
    /// Construct a failure in Construction phase with no card status or credential.
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            phase: Phase::Construction,
            status_word: None,
            reference: None,
            retries_remaining: None,
        }
    }
    /// Replace the phase while retaining all other error details.
    pub fn at(mut self, phase: Phase) -> Self {
        self.phase = phase;
        self
    }
    /// Classify a card status using its phase and optional credential reference.
    ///
    /// SELECT 6A82/6A88 maps to UnsupportedDevice; elsewhere it maps to NotFound.
    /// 63Cx is AuthenticationFailed only with a credential reference. Unknown
    /// statuses remain UnexpectedStatusWord with their raw value. This function
    /// is for failure paths: even 9000 maps to UnexpectedStatusWord here.
    pub fn status(sw: StatusWord, phase: Phase, reference: Option<SecretReference>) -> Self {
        let pin_reference = matches!(
            reference,
            Some(SecretReference::Pin | SecretReference::Puk | SecretReference::AdminPin)
        );
        let kind = match sw.raw() {
            0x6983 if pin_reference => ErrorKind::PinBlocked,
            0x6982 => ErrorKind::SecurityStatusNotSatisfied,
            0x6985 => ErrorKind::ConditionsNotSatisfied,
            0x6a82 | 0x6a88 if phase == Phase::Select => ErrorKind::UnsupportedDevice,
            0x6a82 | 0x6a88 => ErrorKind::NotFound,
            0x6d00 | 0x6e00 => ErrorKind::UnsupportedFeature,
            n if n & 0xfff0 == 0x63c0 && reference.is_some() => ErrorKind::AuthenticationFailed,
            _ => ErrorKind::UnexpectedStatusWord,
        };
        Self {
            kind,
            phase,
            status_word: Some(sw),
            reference,
            retries_remaining: if pin_reference && sw.raw() & 0xfff0 == 0x63c0 {
                Some((sw.raw() & 15) as u8)
            } else {
                None
            },
        }
    }
}
