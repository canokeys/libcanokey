use crate::StatusWord;
use std::fmt;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    InvalidArgument,
    InvalidPin,
    InvalidResponse,
    ProtocolViolation,
    LimitExceeded,
    AuthenticationFailed,
    PinBlocked,
    SecurityStatusNotSatisfied,
    ConditionsNotSatisfied,
    NotFound,
    UnsupportedDevice,
    UnsupportedFeature,
    UnsupportedAlgorithm,
    CapabilityUnknown,
    UnsupportedProtocolVersion,
    UnexpectedStatusWord,
    OperationStateError,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Construction,
    Select,
    Command,
    Authentication,
    Parsing,
    Conversation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretReference {
    Pin,
    Puk,
    ManagementKey,
    AdminPin,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub phase: Phase,
    pub status_word: Option<StatusWord>,
    pub reference: Option<SecretReference>,
    pub retries_remaining: Option<u8>,
}
impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            phase: Phase::Construction,
            status_word: None,
            reference: None,
            retries_remaining: None,
        }
    }
    pub fn at(mut self, phase: Phase) -> Self {
        self.phase = phase;
        self
    }
    pub fn status(sw: StatusWord, phase: Phase, reference: Option<SecretReference>) -> Self {
        let kind = match sw.raw() {
            0x6983 if reference.is_some() => ErrorKind::PinBlocked,
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
            retries_remaining: if reference.is_some() && sw.raw() & 0xfff0 == 0x63c0 {
                Some((sw.raw() & 15) as u8)
            } else {
                None
            },
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} during {:?}", self.kind, self.phase)
    }
}
impl std::error::Error for Error {}
