//! Explicit streaming modes; mode selection never depends implicitly on input size.
use crate::*;
use canokey_protocol::{operation::Continuation, tlv::TlvWriter};

/// Owned full-message signing request. Empty messages are supported in all modes.
/// No host prehash or context substitution occurs; firmware generates signing randomness.
#[derive(Debug)]
pub enum StreamingSignInput {
    /// Pure ML-DSA-65 with an empty context. Nonempty context and HashML-DSA are
    /// not representable because the evidenced firmware hardcodes the empty context.
    MlDsa65(SecretBytes),
    /// Randomized Ed25519 using firmware's explicit FF mode. Signatures verify as
    /// Ed25519 but are not deterministic. This is not Ed25519ph or Ed25519ctx.
    Ed25519Randomized(SecretBytes),
    /// SM2: firmware computes SM3(ZA || message) using the selected key and ID.
    Sm2 {
        /// Full message, including an empty message.
        message: SecretBytes,
        /// Optional 1..=32 byte identity. None requests the firmware default
        /// (the ASCII identity 1234567812345678); Some(empty) is invalid.
        user_id: Option<Vec<u8>>,
    },
}
impl StreamingSignInput {
    /// Semantic key algorithm, independent of the streaming wire-mode selector.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::MlDsa65(_) => Algorithm::MlDsa65,
            Self::Ed25519Randomized(_) => Algorithm::Ed25519,
            Self::Sm2 { .. } => Algorithm::Sm2,
        }
    }
    pub(crate) fn input_len(&self) -> usize {
        match self {
            Self::MlDsa65(m) | Self::Ed25519Randomized(m) => m.len(),
            Self::Sm2 { message, user_id } => message
                .len()
                .saturating_add(user_id.as_ref().map_or(0, Vec::len)),
        }
    }
}
/// Sign a complete owned message using an explicitly selected streaming mode.
/// Selects PIV, applies Access once, and streams the message under that selection.
/// SM2 always starts with a chained prefix, even for empty/small messages. Results
/// retain raw ML-DSA/Ed25519 or P1363 SM2 encoding, with EC conversion getters.
///
/// # Errors
/// Requires evidenced 3.1.0 firmware and observed enabled algorithm IDs. Invalid
/// SM2 IDs, host budgets or a TLV body larger than 65535 bytes fail before SELECT.
/// Intermediate acknowledgements must be empty 9000; failures/cancellation stop
/// without replay. Cancellation is local; the caller must isolate/drain pending I/O.
pub fn sign_streaming(
    profile: &DeviceProfile,
    slot: Slot,
    input: StreamingSignInput,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<Signature>, Error> {
    let target = prepare_sign_streaming(profile, slot, input, options)?;
    access::with_access(profile, access, target, options)
}

pub(crate) struct StreamingMachine {
    prefix: Option<LogicalCommand>,
    awaiting_prefix: bool,
    target: Sequence<Signature>,
}
impl Machine<Signature> for StreamingMachine {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<Signature>, Error> {
        if let Some(prefix) = self.prefix.take() {
            self.awaiting_prefix = true;
            return Ok(Action::Command(prefix));
        }
        if self.awaiting_prefix {
            let response = response.ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
            response.ensure_success(Phase::Conversation)?;
            if !response.data.is_empty() {
                return Err(Error::new(ErrorKind::ProtocolViolation).at(Phase::Conversation));
            }
            self.awaiting_prefix = false;
            self.target.next(None)
        } else {
            self.target.next(response)
        }
    }
}
pub(crate) fn prepare_sign_streaming(
    profile: &DeviceProfile,
    slot: Slot,
    input: StreamingSignInput,
    options: OperationOptions,
) -> Result<StreamingMachine, Error> {
    options.validate()?;
    let algorithm = input.algorithm();
    profile.streaming_signing_support(algorithm).require()?;
    let id = keys::key_id(profile, slot, algorithm)?;
    let id = if algorithm == Algorithm::Ed25519 {
        0xff
    } else {
        id
    };
    if input.input_len() > options.limits.max_input_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let (message, user_id) = match input {
        StreamingSignInput::MlDsa65(m) | StreamingSignInput::Ed25519Randomized(m) => (m, None),
        StreamingSignInput::Sm2 { message, user_id } => (message, user_id),
    };
    let mut inner = TlvWriter::new(options.limits.max_input_bytes.min(65535));
    if let Some(id) = user_id {
        if id.is_empty() || id.len() > 32 {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        inner.push(Tag::from_bytes(&[0x80])?, &id)?;
    }
    inner.push(Tag::from_bytes(&[0x82])?, &[])?;
    inner.push(Tag::from_bytes(&[0x81])?, message.as_bytes())?;
    let mut outer = TlvWriter::new(options.limits.max_input_bytes);
    outer.push(Tag::from_bytes(&[0x7c])?, inner.into_bytes().as_bytes())?;
    let bytes = outer.into_bytes();
    let (prefix, data) = if algorithm == Algorithm::Sm2 {
        // Firmware selects full-message SM2 only on a chained first frame. Send
        // just the outer tag, so an empty message cannot finish on that frame.
        let mut prefix =
            keys::key_command(0x87, id, slot.reference(), SecretBytes::new(vec![0x7c]));
        prefix.header.cla = 0x10;
        prefix.allow_chaining = false;
        prefix.allow_extended = false;
        prefix.continuation = Continuation::None;
        canokey_protocol::operation::validate_command(&prefix, options)?;
        (
            Some(prefix),
            SecretBytes::new(bytes.as_bytes()[1..].to_vec()),
        )
    } else {
        (None, bytes)
    };
    let mut command = keys::key_command(0x87, id, slot.reference(), data);
    command.allow_extended = false;
    let encoding = if algorithm == Algorithm::Sm2 {
        SignatureEncoding::P1363
    } else {
        SignatureEncoding::Raw
    };
    Ok(StreamingMachine {
        prefix,
        awaiting_prefix: false,
        target: access::prepare(command, options, move |r| {
            private::parse_signature(
                algorithm,
                encoding,
                r,
                options.limits.max_total_response_bytes,
            )
        })?,
    })
}
