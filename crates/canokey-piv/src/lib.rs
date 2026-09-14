//! PIV selection, PIN/PUK, management authentication, and object/certificate I/O.
//! # High-level operations
//!
//! Factories such as [`verify_pin`], [`read_object`] and [`read_certificate`] return
//! owned [`Operation`] values. Each selects PIV and performs explicit authentication
//! before its target command; the caller must hold the connection exclusively until
//! completion/failure. Constructors copy required profile configuration and own
//! inputs, so the source profile may be dropped immediately. No transport, login
//! cache, or global device state is retained.
//!
//! # Errors
//!
//! All high-level factories require an observed PIV capability: Unsupported and
//! Unknown produce distinct errors. Invalid budgets or unencodable known commands
//! fail at construction. Card status, response parsing and exhausted conversation
//! budgets fail during start/advance and are retained in the operation. Authentication
//! failures retain credential reference and any reported retries. Never automatically
//! retry a credential submission or mutation.
//!
//! # Example: explicit PIN verification
//!
//! ```
//! use canokey_compat::{DeviceObservations, DeviceProfile, PivApplicationVersion};
//! use canokey_piv::{verify_pin, Pin};
//! use canokey_protocol::{ErrorKind, Step};
//! // Synthetic observations for an offline transcript, not a hardware attestation.
//! let mut observed = DeviceObservations::new(b"3.1.0".to_vec());
//! observed.piv_version = Some(PivApplicationVersion([5, 7, 0]));
//! let profile = DeviceProfile::from_observations(observed)?;
//! let mut op = verify_pin(&profile, Pin::from_bytes(b"123456")?, Default::default())?;
//! drop(profile);
//! assert_eq!(op.start()?, Step::Exchange);
//! assert_eq!(op.command()?.as_bytes(), &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8]);
//! op.advance(&[0x90, 0])?;
//! assert_eq!(op.command()?.as_bytes(),
//!     &[0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff]);
//! let error = op.advance(&[0x63, 0xc2]).unwrap_err();
//! assert_eq!(error.kind, ErrorKind::AuthenticationFailed);
//! assert_eq!(error.retries_remaining, Some(2));
//! // Report the failure; do not retry or try a default PIN.
//! # Ok::<(), canokey_protocol::Error>(())
//! ```
//!
//! The [`command`] module is lower-level: its builders do not SELECT or authenticate
//! on behalf of the caller. Use [`Access::Management`] or [`Access::PinAndManagement`] to keep
//! authentication and a dependent operation under one SELECT.
//!
#![deny(missing_docs)]
#![forbid(unsafe_code)]
mod access;
mod context;
pub use context::{
    decapsulate_in_context, decrypt_in_context, derive_in_context, get_metadata_in_context,
    read_certificate_in_context, sign_in_context, sign_streaming_in_context, PivAccessContext,
    PivAccessState,
};
/// SM2 agreement with explicitly pre-exchanged peer keys.
pub mod sm2_agreement;
pub use sm2_agreement::{agree_sm2, Sm2Agreement, Sm2AgreementInput, Sm2Role};
/// Compact directory observations and per-entry diagnostics.
pub mod directory;
pub use directory::{read_metadata_directory, DirectoryEntry, DirectoryIssue, MetadataDirectory};
/// Explicit PIV configuration changes and key lifecycle operations.
pub mod configuration;
pub use configuration::{
    attest, delete_key, move_key, read_container_name, reset_pin_puk_retries, reset_piv,
    set_algorithm_config, set_container_name, ContainerName,
};
/// Explicit firmware streaming signature modes.
pub mod streaming;
pub use streaming::{sign_streaming, StreamingSignInput};
/// Explicit multi-request operations under one SELECT.
pub mod batch;
pub use batch::{batch, batch_progress, BatchItem, BatchRequest, BatchResults};
/// Signing, decryption, derivation and signature encodings.
pub mod private;
pub use private::{decapsulate, decrypt, derive, sign, SignInput, Signature, SignatureEncoding};
/// Key generation, import material and policies.
pub mod keys;
pub use keys::{generate_key, import_key, KeyParameters, PrivateKeyMaterial};
/// Owned metadata records and key policy values.
pub mod metadata;
pub use metadata::{
    get_metadata, read_algorithm_config, KeyOrigin, KnownOrUnknown, Metadata, MetadataFields,
    MetadataReference, PinPolicy, TouchPolicy,
};
/// Owned public-key fields and standard SPKI encoding.
pub mod public_key;
pub use public_key::PublicKey;
/// Authenticated object/certificate writes and management-key replacement.
pub mod write;
pub use write::{
    delete_certificate, set_management_key, write_certificate, write_object, ManagementTouchPolicy,
};
/// Management-key types and explicit External/Mutual authentication.
pub mod management;
pub use management::{
    authenticate_management_key, ManagementAuthentication, ManagementKey, ManagementKeyAlgorithm,
};
/// Certificate container parsing and bounded gzip decoding.
pub mod certificate;
pub use canokey_compat::Algorithm;
use canokey_compat::{Capability, DeviceProfile};
use canokey_protocol::operation::{
    engine::{Action, Machine},
    LogicalCommand, ResponseData,
};
use canokey_protocol::tlv::{Tag, TlvLimits, TlvReader};
use canokey_protocol::{
    Error, ErrorKind, Operation, OperationOptions, Phase, SecretBytes, SecretReference, StatusWord,
};
pub use certificate::Certificate;
use std::collections::VecDeque;

/// Owned PIV user PIN, redacted in Debug and zeroized on drop.
/// Cloning creates another protected copy with its own lifetime.
#[derive(Clone, Debug)]
pub struct Pin(SecretBytes);
/// Owned PIV unblocking key, redacted in Debug and zeroized on drop.
#[derive(Clone, Debug)]
pub struct Puk(SecretBytes);
fn secret(bytes: &[u8]) -> Result<SecretBytes, Error> {
    if !(6..=8).contains(&bytes.len()) || bytes.contains(&0xff) {
        return Err(Error::new(ErrorKind::InvalidPin));
    }
    Ok(SecretBytes::new(bytes.to_vec()))
}
impl Pin {
    /// Validate and copy raw credential bytes without string conversion.
    ///
    /// # Errors
    /// Credential constructors return [`ErrorKind::InvalidPin`] unless length is
    /// 6..=8 bytes and no byte is FF. Padding is applied only when encoding a command.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(secret(bytes)?))
    }
}
impl Puk {
    /// Validate and copy raw credential bytes without string conversion.
    ///
    /// # Errors
    /// Credential constructors return [`ErrorKind::InvalidPin`] unless length is
    /// 6..=8 bytes and no byte is FF. Padding is applied only when encoding a command.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(secret(bytes)?))
    }
}
/// Authentication to perform after SELECT within one high-level operation.
/// This is an owned input, not a persistent authorization token.
#[derive(Clone, Debug)]
pub enum Access {
    /// Perform no explicit authentication; the card may still reject access.
    None,
    /// Verify the supplied PIN immediately before the target command.
    Pin(Pin),
    /// Authenticate with an explicitly selected management-key mode.
    Management(ManagementAuthentication),
    /// Authenticate management first, then verify PIN immediately before the target.
    PinAndManagement {
        /// Owned user PIN.
        pin: Pin,
        /// Owned key and mode, with caller-provided randomness for Mutual.
        management: ManagementAuthentication,
    },
}
/// PIV key slot, excluding the 9B management-key reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// Authentication key, reference 9A.
    Authentication,
    /// Digital-signature key, reference 9C.
    Signature,
    /// Key-management key, reference 9D.
    KeyManagement,
    /// Card-authentication key, reference 9E.
    CardAuthentication,
    /// Retired key-management slot, reference 82..95.
    Retired(RetiredSlot),
}
/// Checked retired-slot index 1..=20. Valid syntax does not prove card support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredSlot(u8);
impl RetiredSlot {
    /// Construct a retired slot from its one-based index, not its wire reference.
    ///
    /// # Errors
    /// Returns [`ErrorKind::InvalidArgument`] outside 1..=20.
    pub fn new(index: u8) -> Result<Self, Error> {
        if (1..=20).contains(&index) {
            Ok(Self(index))
        } else {
            Err(Error::new(ErrorKind::InvalidArgument))
        }
    }
}
impl Slot {
    /// Return the PIV key reference byte; it is not an object identifier.
    pub fn reference(self) -> u8 {
        match self {
            Self::Authentication => 0x9a,
            Self::Signature => 0x9c,
            Self::KeyManagement => 0x9d,
            Self::CardAuthentication => 0x9e,
            Self::Retired(n) => 0x81 + n.0,
        }
    }
}
/// Checked complete BER object tag (for example, 5F C1 05 or 7E).
/// Use [`Self::certificate`] for library-owned slot-to-certificate mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectId(Tag);
impl ObjectId {
    /// Parse and copy exactly one complete BER tag, with no length/value bytes.
    ///
    /// # Errors
    /// Returns InvalidResponse for malformed, truncated, oversized or trailing
    /// tag bytes. Syntactically valid IDs are not guaranteed to exist on the card.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(Tag::from_bytes(bytes)?))
    }
    /// Map a key slot to its certificate object ID, without probing availability.
    pub fn certificate(slot: Slot) -> Self {
        let last = match slot {
            Slot::Authentication => 5,
            Slot::Signature => 10,
            Slot::KeyManagement => 11,
            Slot::CardAuthentication => 1,
            Slot::Retired(n) => 12 + n.0,
        };
        // All constructed tags are valid BER tags.
        Self(Tag::from_bytes(&[0x5f, 0xc1, last]).expect("fixed PIV tag"))
    }
    /// Copy the complete BER tag encoding, with no length or value bytes.
    pub fn as_bytes(self) -> Vec<u8> {
        self.0.to_bytes()
    }
}
/// Owned raw successful SELECT response data; no login guarantee.
#[derive(Debug)]
pub struct SelectionInfo {
    /// SELECT response bytes excluding status words, retained in a protected buffer.
    pub data: SecretBytes,
}
/// Observation from empty VERIFY. Unknown fields are never synthesized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinStatus {
    /// Some(true) for 9000, Some(false) for retry/blocked statuses.
    pub verified: Option<bool>,
    /// Remaining attempts from 63Cx or zero for blocked; unknown after 9000.
    pub retries_remaining: Option<u8>,
    /// Total configured attempts; currently not reported by this query.
    pub retries_total: Option<u8>,
    /// Whether the card returned the blocked status 6983.
    pub blocked: bool,
}
/// Whether a successful mutation invalidates the capability snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileEffect {
    /// Existing profile remains applicable; application object caches may still change.
    Unchanged,
    /// Caller must discard and rebuild its profile before subsequent operations.
    ReprobeRequired,
}
/// Successful mutation outcome, without claiming application caches were refreshed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutationResult {
    /// Profile invalidation decision; PIN/PUK changes currently return Unchanged.
    pub profile_effect: ProfileEffect,
}
/// Owned normalized object value with zeroization; excludes the outer container.
pub type ObjectData = SecretBytes;
fn unchanged() -> MutationResult {
    MutationResult {
        profile_effect: ProfileEffect::Unchanged,
    }
}
fn require(profile: &DeviceProfile) -> Result<(), Error> {
    profile.capability(Capability::Piv).require()
}
fn auth_error(sw: StatusWord, reference: SecretReference) -> Error {
    Error::status(sw, Phase::Authentication, Some(reference))
}
fn require_auth(response: &ResponseData, reference: SecretReference) -> Result<(), Error> {
    if response.status.is_success() {
        Ok(())
    } else {
        Err(auth_error(response.status, reference))
    }
}

/// Raw PIV logical-command builders.
///
/// Except for `select`, these require PIV to be selected already. They do not
/// perform authentication, status mapping, or capability checks. Prefer the
/// crate-level factories for complete standalone operations.
pub mod command {
    use super::*;
    use canokey_protocol::{ApduHeader, ExpectedLength};
    fn cmd(ins: u8, p1: u8, p2: u8, data: Vec<u8>, le: ExpectedLength) -> LogicalCommand {
        LogicalCommand::new(ApduHeader::new(0, ins, p1, p2), data, le)
    }
    /// Build SELECT PIV. This can invalidate card authentication state.
    /// Construct a standalone SELECT PIV operation returning raw selection data.
    ///
    /// # Errors
    /// See the [crate-level errors](crate#errors). A missing applet fails during
    /// execution; successful selection is not proof of retained authentication.
    pub fn select() -> LogicalCommand {
        cmd(0xa4, 4, 0, vec![0xa0, 0, 0, 3, 8], ExpectedLength::Absent)
    }
    fn read(ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> LogicalCommand {
        let mut c = cmd(ins, p1, p2, data, ExpectedLength::Exact(256));
        c.correct_le = true;
        c
    }
    /// Build GET VERSION for the PIV application, not actual CanoKey firmware.
    pub fn version() -> LogicalCommand {
        read(0xfd, 0, 0, vec![])
    }
    /// Build algorithm-configuration discovery; the caller must establish probe safety.
    pub fn algorithm_config() -> LogicalCommand {
        read(0xee, 1, 0, vec![])
    }
    /// Build an individual metadata read; does not query the metadata directory.
    pub fn metadata(reference: MetadataReference) -> LogicalCommand {
        read(0xf7, 0, reference.reference(), vec![])
    }
    /// Build empty VERIFY. Interpret 63Cx as status data, not a submitted-PIN failure.
    pub fn pin_status() -> LogicalCommand {
        read(0x20, 0, 0x80, vec![])
    }
    fn padded(secret: &SecretBytes) -> Vec<u8> {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(secret.as_bytes());
        data.resize(8, 0xff);
        data
    }
    /// Copy and FF-pad a PIN to eight bytes for VERIFY reference 80.
    /// Construct SELECT followed by explicit PIN verification.
    ///
    /// Success returns `()` but creates no authorization token for later SELECTs.
    /// The operation owns the PIN; it is never retried after credential failure.
    ///
    /// # Errors
    /// See the [crate-level errors](crate#errors). During execution, 63Cx becomes
    /// AuthenticationFailed with retries and PIN reference; 6983 becomes PinBlocked.
    pub fn verify_pin(pin: &Pin) -> LogicalCommand {
        cmd(0x20, 0, 0x80, padded(&pin.0), ExpectedLength::Absent)
    }
    /// Build VERIFY with P1 FF to clear PIV PIN verification state.
    pub fn logout() -> LogicalCommand {
        cmd(0x20, 0xff, 0x80, vec![], ExpectedLength::Exact(256))
    }
    pub(super) fn change(
        ins: u8,
        reference: u8,
        old: &SecretBytes,
        new: &SecretBytes,
    ) -> LogicalCommand {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(old.as_bytes());
        data.resize(8, 0xff);
        data.extend_from_slice(new.as_bytes());
        data.resize(16, 0xff);
        cmd(ins, 0, reference, data, ExpectedLength::Absent)
    }
    /// Build GET DATA with a complete 5C object identifier field.
    pub fn get_data(id: ObjectId) -> LogicalCommand {
        let tag = id.as_bytes();
        let mut data = vec![0x5c, tag.len() as u8];
        data.extend(tag);
        read(0xcb, 0x3f, 0xff, data)
    }
}
struct Request {
    command: LogicalCommand,
    phase: Phase,
    reference: Option<SecretReference>,
}
type Parser<T> = Box<dyn FnOnce(ResponseData) -> Result<T, Error> + Send>;
pub(crate) struct Sequence<T> {
    pending: VecDeque<Request>,
    current: Option<(Phase, Option<SecretReference>)>,
    parse: Option<Parser<T>>,
}
impl<T> Machine<T> for Sequence<T> {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<T>, Error> {
        if let Some(response) = response {
            if self.pending.is_empty() {
                return Ok(Action::Done(self
                    .parse
                    .take()
                    .ok_or_else(|| Error::new(ErrorKind::OperationStateError))?(
                    response,
                )?));
            }
            let (phase, reference) = self
                .current
                .ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
            if !response.status.is_success() {
                return Err(Error::status(response.status, phase, reference));
            }
        }
        let req = self
            .pending
            .pop_front()
            .ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
        self.current = Some((req.phase, req.reference));
        Ok(Action::Command(req.command))
    }
}
fn make<T: 'static>(
    profile: &DeviceProfile,
    mut commands: Vec<Request>,
    options: OperationOptions,
    parse: impl FnOnce(ResponseData) -> Result<T, Error> + Send + 'static,
) -> Result<Operation<T>, Error> {
    options.validate()?;
    for request in &mut commands {
        if profile.legacy_explicit_le()
            && request.command.le == canokey_protocol::ExpectedLength::Absent
        {
            request.command.le = canokey_protocol::ExpectedLength::Exact(256);
        }
        canokey_protocol::operation::validate_command(&request.command, options)?;
    }
    Operation::from_machine(
        Sequence {
            pending: commands.into(),
            current: None,
            parse: Some(Box::new(parse)),
        },
        options,
    )
}
pub(crate) fn operation_from_sequence<T: 'static>(
    profile: &DeviceProfile,
    mut sequence: Sequence<T>,
    options: OperationOptions,
) -> Result<Operation<T>, Error> {
    if profile.legacy_explicit_le() {
        for request in &mut sequence.pending {
            if request.command.le == canokey_protocol::ExpectedLength::Absent {
                request.command.le = canokey_protocol::ExpectedLength::Exact(256);
            }
        }
    }
    for request in &sequence.pending {
        canokey_protocol::operation::validate_command(&request.command, options)?;
    }
    Operation::from_machine(sequence, options)
}

pub(crate) fn operation_from_machine<T: 'static>(
    machine: impl Machine<T> + 'static,
    options: OperationOptions,
) -> Result<Operation<T>, Error> {
    options.validate()?;
    Operation::from_machine(machine, options)
}
fn request(command: LogicalCommand, phase: Phase, reference: Option<SecretReference>) -> Request {
    Request {
        command,
        phase,
        reference,
    }
}
fn selected(command: LogicalCommand) -> Vec<Request> {
    vec![
        request(command::select(), Phase::Select, None),
        request(command, Phase::Command, None),
    ]
}
/// Construct a standalone SELECT PIV operation returning raw selection data.
///
/// # Errors
/// See the [crate-level errors](crate#errors). A missing applet fails during
/// execution; successful selection is not proof of retained authentication.
pub fn select(
    profile: &DeviceProfile,
    options: OperationOptions,
) -> Result<Operation<SelectionInfo>, Error> {
    require(profile)?;
    make(
        profile,
        vec![request(command::select(), Phase::Select, None)],
        options,
        |r| {
            r.ensure_success(Phase::Select)?;
            Ok(SelectionInfo { data: r.data })
        },
    )
}
/// Construct SELECT followed by explicit PIN verification.
///
/// Success returns `()` but creates no authorization token for later SELECTs.
/// The operation owns the PIN; it is never retried after credential failure.
///
/// # Errors
/// See the [crate-level errors](crate#errors). During execution, 63Cx becomes
/// AuthenticationFailed with retries and PIN reference; 6983 becomes PinBlocked.
pub fn verify_pin(
    profile: &DeviceProfile,
    pin: Pin,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    require(profile)?;
    make(profile, selected(command::verify_pin(&pin)), options, |r| {
        require_auth(&r, SecretReference::Pin)
    })
}
/// Construct SELECT followed by an empty VERIFY status query.
///
/// This performs no credential submission and does not discover total attempts.
/// The initial SELECT may clear prior PIN verification.
///
/// # Errors
/// See the [crate-level errors](crate#errors). Nonempty response data is invalid;
/// 9000, 63Cx and 6983 are typed status results, while other statuses are errors.
pub fn get_pin_status(
    profile: &DeviceProfile,
    options: OperationOptions,
) -> Result<Operation<PinStatus>, Error> {
    require(profile)?;
    make(profile, selected(command::pin_status()), options, |r| {
        if !r.data.is_empty() {
            return Err(Error::new(ErrorKind::InvalidResponse));
        }
        match r.status.raw() {
            0x9000 => Ok(PinStatus {
                verified: Some(true),
                retries_remaining: None,
                retries_total: None,
                blocked: false,
            }),
            0x6983 => Ok(PinStatus {
                verified: Some(false),
                retries_remaining: Some(0),
                retries_total: None,
                blocked: true,
            }),
            sw if sw & 0xfff0 == 0x63c0 => Ok(PinStatus {
                verified: Some(false),
                retries_remaining: Some((sw & 15) as u8),
                retries_total: None,
                blocked: false,
            }),
            _ => Err(auth_error(r.status, SecretReference::Pin)),
        }
    })
}
/// Construct SELECT followed by explicit PIV PIN logout.
///
/// This does not close the application connection. Dropping an operation alone
/// does not run this command.
///
/// # Errors
/// See the [crate-level errors](crate#errors); card failures propagate.
pub fn logout(profile: &DeviceProfile, options: OperationOptions) -> Result<Operation<()>, Error> {
    require(profile)?;
    make(profile, selected(command::logout()), options, |r| {
        r.ensure_success(Phase::Authentication)
    })
}
/// Construct SELECT followed by CHANGE REFERENCE DATA for the user PIN.
///
/// Owns both PINs. A successful result has Unchanged profile effect. This mutates
/// card state; an I/O failure may leave the outcome uncertain and must not replay.
///
/// # Errors
/// See the [crate-level errors](crate#errors). Credential failures identify Pin.
pub fn change_pin(
    profile: &DeviceProfile,
    old: Pin,
    new: Pin,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    change_secret(
        profile,
        0x24,
        0x80,
        &old.0,
        &new.0,
        SecretReference::Pin,
        options,
    )
}
/// Construct SELECT followed by CHANGE REFERENCE DATA for the PUK.
///
/// Owns both PUKs. This mutates card state; do not retry after uncertain I/O.
///
/// # Errors
/// See the [crate-level errors](crate#errors). Credential failures identify Puk.
pub fn change_puk(
    profile: &DeviceProfile,
    old: Puk,
    new: Puk,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    change_secret(
        profile,
        0x24,
        0x81,
        &old.0,
        &new.0,
        SecretReference::Puk,
        options,
    )
}
/// Construct SELECT followed by RESET RETRY COUNTER with PUK and replacement PIN.
///
/// Owns both credentials. This mutates card state; do not retry after uncertain I/O.
///
/// # Errors
/// See the [crate-level errors](crate#errors). Credential failures identify Puk.
pub fn unblock_pin(
    profile: &DeviceProfile,
    puk: Puk,
    new_pin: Pin,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    change_secret(
        profile,
        0x2c,
        0x80,
        &puk.0,
        &new_pin.0,
        SecretReference::Puk,
        options,
    )
}
fn change_secret(
    profile: &DeviceProfile,
    ins: u8,
    p2: u8,
    old: &SecretBytes,
    new: &SecretBytes,
    reference: SecretReference,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    require(profile)?;
    make(
        profile,
        selected(command::change(ins, p2, old, new)),
        options,
        move |r| {
            require_auth(&r, reference)?;
            Ok(unchanged())
        },
    )
}
/// Construct SELECT, optional PIN verification, and GET DATA.
///
/// Return the outer 53 value (7E for discovery), with narrow legacy CCC/CHUID
/// normalization from the profile. No extra SELECT occurs after authentication.
/// The result remains protected by [`SecretBytes`].
///
/// # Errors
/// See the [crate-level errors](crate#errors). Missing objects return NotFound;
/// malformed containers or extra fields do not become empty successful reads.
pub fn read_object(
    profile: &DeviceProfile,
    id: ObjectId,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<ObjectData>, Error> {
    read_object_with(profile, id, access, options, Ok)
}

/// Read and unwrap a certificate, with bounded gzip decompression.
/// This does not validate X.509 syntax, signatures, or trust.
/// The operation selects PIV, optionally verifies PIN, then reads the mapped
/// certificate object. Both container and decoded output use the cumulative
/// response-byte budget. The result owns its bytes independently of the operation.
///
/// # Errors
/// See the [crate-level errors](crate#errors). NotFound remains a card-status
/// error. Malformed containers/gzip fail; unsupported information flags return
/// UnsupportedProtocolVersion; oversized decoded payloads return LimitExceeded.
/// See [`Certificate::from_object`] for the accepted container format.
pub fn read_certificate(
    profile: &DeviceProfile,
    slot: Slot,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<Certificate>, Error> {
    let limit = options.limits.max_total_response_bytes;
    read_object_with(
        profile,
        ObjectId::certificate(slot),
        access,
        options,
        move |data| Certificate::from_object(data.as_bytes(), limit),
    )
}

fn read_object_with<T: 'static>(
    profile: &DeviceProfile,
    id: ObjectId,
    access: Access,
    options: OperationOptions,
    parse: impl FnOnce(ObjectData) -> Result<T, Error> + Send + 'static,
) -> Result<Operation<T>, Error> {
    let target = prepare_read_object_with(profile, id, options, parse)?;
    access::with_access(profile, access, target, options)
}

pub(crate) fn prepare_read_object_with<T: 'static>(
    profile: &DeviceProfile,
    id: ObjectId,
    options: OperationOptions,
    parse: impl FnOnce(ObjectData) -> Result<T, Error> + Send + 'static,
) -> Result<Sequence<T>, Error> {
    require(profile)?;
    let legacy = profile.legacy_unwrapped_objects();
    let limit = options.limits.max_total_response_bytes;
    access::prepare(command::get_data(id), options, move |r| {
        r.ensure_success(Phase::Command)?;
        let data = r.data.as_bytes();
        if legacy
            && ((id.0.value() == 0x5fc102 && data.first() == Some(&0x30))
                || (id.0.value() == 0x5fc107 && data.first() == Some(&0xf0)))
        {
            return parse(r.data);
        }
        let mut reader = TlvReader::new(
            data,
            TlvLimits {
                max_value_bytes: limit,
                ..Default::default()
            },
        );
        let tlv = reader
            .next()?
            .ok_or_else(|| Error::new(ErrorKind::InvalidResponse))?;
        if tlv.tag.value() != if id.0.value() == 0x7e { 0x7e } else { 0x53 }
            || reader.next()?.is_some()
        {
            return Err(Error::new(ErrorKind::InvalidResponse));
        }
        parse(SecretBytes::new(tlv.value.to_vec()))
    })
}
