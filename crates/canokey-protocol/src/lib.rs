//! Transport-free APDU conversations and caller-owned operations.
#![forbid(unsafe_code)]
pub mod apdu;
pub mod error;
pub mod operation;
pub mod tlv;
pub use apdu::{ApduEncoding, ApduHeader, CommandApdu, ExpectedLength, ResponseApdu, StatusWord};
pub use error::{Error, ErrorKind, Phase, SecretReference};
pub use operation::{
    ExchangeOptions, Operation, OperationLimits, OperationOptions, OperationState, Step,
};
use std::fmt;
use zeroize::Zeroizing;

/// Owned sensitive bytes. Debug is redacted; the allocation is zeroized on drop.
#[derive(Clone, Default)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);
impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Append bytes, wiping the old allocation if growth requires replacement.
    pub fn extend(&mut self, data: &[u8]) {
        if data.len() > self.0.capacity() - self.0.len() {
            // Vec::reserve would free a previous allocation without wiping it.
            let mut next = Zeroizing::new(Vec::with_capacity(self.0.len() + data.len()));
            next.extend_from_slice(&self.0);
            next.extend_from_slice(data);
            self.0 = next;
        } else {
            self.0.extend_from_slice(data);
        }
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}
