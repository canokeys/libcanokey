//! Caller-owned PIV transaction contexts.
//!
//! Factories copy required profile configuration and own their inputs. They do
//! not perform I/O during construction and their operations never SELECT or
//! authenticate implicitly. The caller holds the selected card transaction until
//! completion or failure. All operations retain terminal errors; dropping a
//! context or operation performs no card cleanup and cannot roll back mutations.
use super::management::{ManagementAuthentication, ManagementMachine};
use crate::{
    Algorithm, Certificate, DeviceProfile, Error, ErrorKind, KeyParameters, Metadata,
    MetadataReference, ObjectId, Operation, OperationOptions, PrivateKeyMaterial, SecretBytes,
    SignInput, Signature, Slot, StreamingSignInput,
};
use canokey_compat::Capability;

/// Authorization state already established by the caller on the selected PIV
/// application. This value contains no card handle and performs no I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PivAccessState {
    /// PIV is selected; no credential is asserted by this context.
    Selected,
    /// The caller has verified the user PIN in the current transaction.
    PinVerified,
    /// The caller has completed management-key authorization.
    ManagementAuthorized,
    /// The caller has completed both management-key and user-PIN authorization.
    PinAndManagementAuthorized,
}

/// A caller-owned view of an already selected PIV transaction.
///
/// Constructing this value never connects, selects, authenticates, or probes.
/// The caller must keep its PC/SC transaction alive until the returned operation
/// reaches completion or failure. The profile is copied so the operation does
/// not borrow mutable caller state.
#[derive(Clone, Debug)]
pub struct PivAccessContext {
    profile: DeviceProfile,
    state: PivAccessState,
}

impl PivAccessContext {
    /// Describe a transaction in which PIV has already been selected.
    ///
    /// # Errors
    /// UnsupportedFeature or CapabilityUnknown reports a profile without known
    /// PIV support. The declared authorization is not checked against a live card.
    pub fn selected(profile: &DeviceProfile) -> Result<Self, Error> {
        Self::from_state(profile, PivAccessState::Selected)
    }
    /// Describe a transaction after user PIN verification.
    ///
    /// # Errors
    /// UnsupportedFeature or CapabilityUnknown reports a profile without known
    /// PIV support. The declared authorization is not checked against a live card.
    pub fn pin_verified(profile: &DeviceProfile) -> Result<Self, Error> {
        Self::from_state(profile, PivAccessState::PinVerified)
    }
    /// Describe a transaction after management-key authorization.
    ///
    /// # Errors
    /// UnsupportedFeature or CapabilityUnknown reports a profile without known
    /// PIV support. The declared authorization is not checked against a live card.
    pub fn management_authorized(profile: &DeviceProfile) -> Result<Self, Error> {
        Self::from_state(profile, PivAccessState::ManagementAuthorized)
    }
    /// Describe a transaction after both required authorizations.
    ///
    /// # Errors
    /// UnsupportedFeature or CapabilityUnknown reports a profile without known
    /// PIV support. The declared authorization is not checked against a live card.
    pub fn pin_and_management_authorized(profile: &DeviceProfile) -> Result<Self, Error> {
        Self::from_state(profile, PivAccessState::PinAndManagementAuthorized)
    }
    /// Return the immutable profile copied into this context.
    pub fn profile(&self) -> &DeviceProfile {
        &self.profile
    }
    /// Return the caller-declared authorization state.
    pub fn state(&self) -> PivAccessState {
        self.state
    }
    /// Construct a context from an explicit caller-declared state.
    ///
    /// This does not inspect or change the card's live authorization state.
    ///
    /// # Errors
    /// UnsupportedFeature or CapabilityUnknown reports a profile without known
    /// PIV support. The declared authorization is not checked against a live card.
    pub fn from_state(profile: &DeviceProfile, state: PivAccessState) -> Result<Self, Error> {
        profile.capability(Capability::Piv).require()?;
        Ok(Self {
            profile: profile.clone(),
            state,
        })
    }
    fn require_management(&self) -> Result<(), Error> {
        if matches!(
            self.state,
            PivAccessState::ManagementAuthorized | PivAccessState::PinAndManagementAuthorized
        ) {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::SecurityStatusNotSatisfied))
        }
    }
}

/// Require fresh, explicit absence before a managed key write.
/// This reads metadata without parsing an occupied key's algorithm or public key:
/// any successful status means occupied, including unknown/malformed key data.
/// The caller holds this transaction and management reservation through the write.
/// # Errors
/// Only an empty 6A82/6A88 response succeeds. Occupied slots return
/// ConditionsNotSatisfied; unsupported commands, malformed absence and other
/// failures block the write. No SELECT, authentication or mutation is performed.
pub fn require_empty_key_slot_in_context(
    context: &PivAccessContext,
    slot: Slot,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    context
        .profile()
        .piv_slot_support(slot.reference())
        .require()?;
    let sequence = super::access::prepare(
        super::command::metadata(MetadataReference::Key(slot)),
        options,
        |response| {
            if response.status.is_success() {
                return Err(Error::new(ErrorKind::ConditionsNotSatisfied)
                    .at(canokey_protocol::Phase::Command));
            }
            if matches!(response.status.raw(), 0x6a82 | 0x6a88) && response.data.is_empty() {
                return Ok(());
            }
            if matches!(response.status.raw(), 0x6a82 | 0x6a88) {
                return Err(
                    Error::new(ErrorKind::InvalidResponse).at(canokey_protocol::Phase::Parsing)
                );
            }
            response.ensure_success(canokey_protocol::Phase::Command)
        },
    )?;
    super::operation_from_sequence(context.profile(), sequence, options)
}

/// Read key, PIN, PUK, or management metadata without SELECT or authentication.
///
/// # Errors
/// Profile/metadata capability failures preserve UnsupportedFeature versus
/// CapabilityUnknown. Invalid options or command budgets fail at construction.
/// During execution, absent metadata returns NotFound; malformed fields return
/// InvalidResponse or ProtocolViolation. Card errors retain their status word.
pub fn get_metadata_in_context(
    context: &PivAccessContext,
    reference: MetadataReference,
    options: OperationOptions,
) -> Result<Operation<Metadata>, Error> {
    let sequence = super::metadata::prepare_get_metadata(&context.profile, reference, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Read and decode a certificate without SELECT or authentication.
///
/// # Errors
/// UnsupportedFeature or CapabilityUnknown reports unavailable PIV support;
/// invalid options and command limits fail at construction. During execution,
/// NotFound denotes an absent certificate; malformed framing/gzip and unsupported
/// certificate flags remain errors. LimitExceeded bounds decompression and responses.
pub fn read_certificate_in_context(
    context: &PivAccessContext,
    slot: Slot,
    options: OperationOptions,
) -> Result<Operation<Certificate>, Error> {
    let limit = options.limits.max_total_response_bytes;
    let sequence = super::prepare_read_object_with(
        &context.profile,
        ObjectId::certificate(slot),
        options,
        move |data| Certificate::from_object(data.as_bytes(), limit),
    )?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Read a PIV data object in the caller's selected transaction.
/// Returns the normalized outer 53 value (7E for discovery), owned as secret bytes.
///
/// # Errors
/// PIV profile, option validation and command encoding errors fail at construction.
/// During execution, NotFound and SecurityStatusNotSatisfied retain card status;
/// malformed object framing and exhausted response budgets are terminal errors.
pub fn read_object_in_context(
    context: &PivAccessContext,
    id: ObjectId,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    let sequence = super::prepare_read_object_with(&context.profile, id, options, Ok)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Set or clear a container name in the already authenticated transaction.
/// The caller retains the transaction and management reservation until completion;
/// this operation never SELECTs, authenticates, retries or updates a host cache.
///
/// # Errors
/// SecurityStatusNotSatisfied rejects a context without management authorization.
/// Profile/feature/slot or command-limit failures occur before I/O. During execution,
/// NotFound means an absent key; firmware uniqueness/status failures are terminal.
/// A lost response may follow a committed write and requires cache invalidation.
pub fn set_container_name_in_context(
    context: &PivAccessContext,
    slot: impl Into<super::ContainerNameReference>,
    name: super::ContainerName,
    options: OperationOptions,
) -> Result<Operation<super::MutationResult>, Error> {
    context.require_management()?;
    let sequence = super::configuration::prepare_set_name(&context.profile, slot, name, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Read the PIV metadata directory in the caller's selected transaction.
///
/// # Errors
/// UnsupportedFeature or CapabilityUnknown reports unavailable directory support.
/// Invalid options or command limits fail at construction. Malformed responses
/// and exhausted response budgets fail during execution; unknown directory versions
/// are retained without inventing decoded entries.
pub fn read_metadata_directory_in_context(
    context: &PivAccessContext,
    options: OperationOptions,
) -> Result<Operation<super::MetadataDirectory>, Error> {
    let sequence = super::directory::prepare_directory(&context.profile, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Read a persisted container name in the caller's selected transaction.
///
/// # Errors
/// Profile, slot and container-name capability errors, invalid options, or command
/// limits fail at construction. NotFound denotes an absent key during execution;
/// malformed UTF-16 and oversized names return InvalidResponse. Card status and
/// conversation-limit errors remain terminal.
pub fn read_container_name_in_context(
    context: &PivAccessContext,
    slot: impl Into<super::ContainerNameReference>,
    options: OperationOptions,
) -> Result<Operation<super::ContainerName>, Error> {
    let sequence = super::configuration::prepare_read_name(&context.profile, slot, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Write a PIV data object after management authorization in the current transaction.
/// Takes ownership of the normalized object value and adds 5C/53 framing.
///
/// # Errors
/// SecurityStatusNotSatisfied means the context lacks management authorization.
/// Profile/write capability, invalid options, and encoded-input limits are checked
/// before execution. Card status and malformed acknowledgments fail during
/// execution; an attempted write may persist despite failure or cancellation.
pub fn write_object_in_context(
    context: &PivAccessContext,
    id: ObjectId,
    data: Vec<u8>,
    options: OperationOptions,
) -> Result<Operation<super::MutationResult>, Error> {
    context.require_management()?;
    let sequence =
        super::write::prepare_write_object(&context.profile, id, SecretBytes::new(data), options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Write an uncompressed DER certificate after management authorization.
/// Owns the payload and adds PIV framing without validating X.509 syntax or trust.
///
/// # Errors
/// SecurityStatusNotSatisfied means management authorization is absent.
/// InvalidArgument rejects an empty payload. UnsupportedFeature, CapabilityUnknown,
/// invalid options and input/command limits reject construction. Execution errors
/// may follow a committed write; dropping the operation does not roll it back.
pub fn write_certificate_in_context(
    context: &PivAccessContext,
    slot: Slot,
    der: Vec<u8>,
    options: OperationOptions,
) -> Result<Operation<super::MutationResult>, Error> {
    context.require_management()?;
    let sequence = super::write::prepare_write_certificate(
        &context.profile,
        slot,
        SecretBytes::new(der),
        options,
    )?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Delete a certificate after management authorization.
///
/// # Errors
/// SecurityStatusNotSatisfied means management authorization is absent.
/// UnsupportedFeature or CapabilityUnknown rejects unevidenced deletion support.
/// Invalid options and command limits fail at construction; execution errors may
/// follow a committed deletion. The associated private key is not deleted.
pub fn delete_certificate_in_context(
    context: &PivAccessContext,
    slot: Slot,
    options: OperationOptions,
) -> Result<Operation<super::MutationResult>, Error> {
    context.require_management()?;
    let sequence = super::write::prepare_delete_certificate(&context.profile, slot, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Generate a PIV key after management authorization in the current transaction.
///
/// # Errors
/// SecurityStatusNotSatisfied means management authorization is absent.
/// UnsupportedFeature, CapabilityUnknown or UnsupportedAlgorithm rejects unsupported
/// profile/slot/algorithm combinations. Invalid parameters, policies, options and
/// command limits fail at construction. Card or public-key parsing errors can follow
/// irreversible generation; no automatic rollback or retry occurs.
pub fn generate_key_in_context(
    context: &PivAccessContext,
    parameters: KeyParameters,
    options: OperationOptions,
) -> Result<Operation<super::PublicKey>, Error> {
    context.require_management()?;
    let sequence = super::keys::prepare_generate_key(&context.profile, parameters, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Import PIV private material after management authorization in the current transaction.
///
/// # Errors
/// SecurityStatusNotSatisfied means management authorization is absent.
/// InvalidArgument rejects mismatched material/algorithm or invalid parameters.
/// Profile, slot, policy and algorithm support, options and command limits are
/// validated before execution. Card errors may follow a partial or committed import;
/// owned secret material is dropped on every exit and no rollback is attempted.
pub fn import_key_in_context(
    context: &PivAccessContext,
    parameters: KeyParameters,
    material: PrivateKeyMaterial,
    options: OperationOptions,
) -> Result<Operation<super::MutationResult>, Error> {
    context.require_management()?;
    let sequence =
        super::keys::prepare_import_key(&context.profile, parameters, material, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Authenticate the management key in the caller's selected transaction.
///
/// # Errors
/// UnsupportedFeature or CapabilityUnknown reports unsupported management-key
/// algorithms for the observed firmware. Invalid options or command budgets fail
/// at construction. During execution, AuthenticationFailed, malformed challenges,
/// and DeviceAuthenticationFailed (mutual mode) remain distinct errors with the
/// management-key reference. This does not update the caller's context state.
pub fn authenticate_management_in_context(
    context: &PivAccessContext,
    auth: ManagementAuthentication,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    auth.validate(&context.profile, options)?;
    super::access::in_context(&context.profile, ManagementMachine::new(auth), options)
}

/// Sign using the caller's existing PIV selection and authorization boundary.
/// PIN policy is intentionally enforced by the caller after metadata discovery;
/// this operation never performs an implicit VERIFY or management login.
///
/// # Errors
/// Profile/slot/algorithm support, input format, options and command limits are
/// validated at construction; incompatible inputs return InvalidArgument or
/// UnsupportedAlgorithm. Card authorization failures and malformed signatures fail
/// during execution. No PIN verification, implicit retry, or result publication
/// occurs after an execution error.
pub fn sign_in_context(
    context: &PivAccessContext,
    slot: Slot,
    algorithm: Algorithm,
    input: SignInput,
    options: OperationOptions,
) -> Result<Operation<Signature>, Error> {
    let sequence = super::private::prepare_sign(&context.profile, slot, algorithm, input, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Sign a complete ML-DSA, Ed25519, or SM2 message using the caller's selected
/// transaction. This operation never performs implicit authentication.
///
/// # Errors
/// Profile/slot/streaming-algorithm support, input format and options are validated
/// at construction. InvalidArgument rejects invalid SM2 user IDs; LimitExceeded
/// bounds the complete message and encoded command. Card authorization, malformed
/// signature and conversation-limit errors fail during execution without replay.
pub fn sign_streaming_in_context(
    context: &PivAccessContext,
    slot: Slot,
    input: StreamingSignInput,
    options: OperationOptions,
) -> Result<Operation<Signature>, Error> {
    let machine = super::streaming::prepare_sign_streaming(&context.profile, slot, input, options)?;
    super::access::in_context(&context.profile, machine, options)
}

/// Perform a raw RSA private operation in the caller's selected transaction.
///
/// # Errors
/// UnsupportedAlgorithm rejects non-RSA algorithms; InvalidArgument rejects a
/// ciphertext with the wrong modulus width. Profile/slot support, options and
/// command limits are checked before execution. Card authorization errors and
/// malformed results fail during execution without returning partial plaintext.
pub fn decrypt_in_context(
    context: &PivAccessContext,
    slot: Slot,
    algorithm: Algorithm,
    ciphertext: SecretBytes,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    let sequence =
        super::private::prepare_decrypt(&context.profile, slot, algorithm, ciphertext, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Derive an unprocessed ECDH/X25519 secret in the caller's selected transaction.
///
/// # Errors
/// UnsupportedAlgorithm rejects algorithms without this agreement operation;
/// InvalidArgument rejects malformed peer encodings. Profile/slot support, options
/// and command limits are validated before execution. Card authorization failures
/// and malformed secrets are terminal, with no partial secret publication.
pub fn derive_in_context(
    context: &PivAccessContext,
    slot: Slot,
    algorithm: Algorithm,
    peer: Vec<u8>,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    let sequence =
        super::private::prepare_derive(&context.profile, slot, algorithm, peer, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Decapsulate an ML-KEM-768 ciphertext in the caller's selected transaction.
///
/// # Errors
/// InvalidArgument rejects ciphertexts whose size is not ML-KEM-768's expected
/// 1088 bytes. Profile/slot/algorithm support, options and command limits fail at
/// construction. Card authorization, malformed secrets and exhausted conversation
/// budgets fail during execution without publishing a partial secret.
pub fn decapsulate_in_context(
    context: &PivAccessContext,
    slot: Slot,
    ciphertext: SecretBytes,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    let sequence =
        super::private::prepare_decapsulate(&context.profile, slot, ciphertext, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Read a validated PIV object while retaining its complete 53/7E container.
/// This compatibility form preserves device bytes for existing raw-object APIs;
/// new value consumers should use [`read_object_in_context`]. The result owns and
/// zeroizes its bytes and no SELECT or authentication is inserted.
///
/// # Errors
/// Profile, options, status, framing and response-limit errors are the same as
/// [`read_object_in_context`]. Malformed containers never become successful reads.
pub fn read_object_container_in_context(
    context: &PivAccessContext,
    id: ObjectId,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    let sequence = super::prepare_read_object_format(&context.profile, id, options, true, Ok)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Write one complete 53 object container in a management-authorized transaction.
/// Owns and validates the container, then emits exactly one 53 wrapper on PUT DATA.
/// This compatibility form is for existing APIs passing framed PIV data, including
/// certificates. Value consumers should use [`write_object_in_context`].
///
/// # Errors
/// SecurityStatusNotSatisfied rejects missing management authorization. Invalid
/// framing, a wrong outer tag, trailing fields, and input limits reject construction.
/// Profile/options/card errors and uncertain-write behavior match [`write_object_in_context`].
pub fn write_object_container_in_context(
    context: &PivAccessContext,
    id: ObjectId,
    container: SecretBytes,
    options: OperationOptions,
) -> Result<Operation<super::MutationResult>, Error> {
    context.require_management()?;
    if container.len() > options.limits.max_input_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let mut reader = canokey_protocol::tlv::TlvReader::new(
        container.as_bytes(),
        canokey_protocol::tlv::TlvLimits {
            max_value_bytes: options.limits.max_input_bytes,
            ..Default::default()
        },
    );
    let value = reader
        .next()?
        .ok_or_else(|| Error::new(ErrorKind::InvalidArgument))?;
    if value.tag.value() != 0x53 || reader.next()?.is_some() {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let sequence = super::write::prepare_write_object(
        &context.profile,
        id,
        SecretBytes::new(value.value.to_vec()),
        options,
    )?;
    super::operation_from_sequence(&context.profile, sequence, options)
}
