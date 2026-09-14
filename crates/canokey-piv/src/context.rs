//! Caller-owned PIV transaction contexts.
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
    pub fn selected(profile: &DeviceProfile) -> Result<Self, Error> {
        Self::from_state(profile, PivAccessState::Selected)
    }
    /// Describe a transaction after user PIN verification.
    pub fn pin_verified(profile: &DeviceProfile) -> Result<Self, Error> {
        Self::from_state(profile, PivAccessState::PinVerified)
    }
    /// Describe a transaction after management-key authorization.
    pub fn management_authorized(profile: &DeviceProfile) -> Result<Self, Error> {
        Self::from_state(profile, PivAccessState::ManagementAuthorized)
    }
    /// Describe a transaction after both required authorizations.
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
    pub fn from_state(profile: &DeviceProfile, state: PivAccessState) -> Result<Self, Error> {
        profile.capability(Capability::Piv).require()?;
        Ok(Self {
            profile: profile.clone(),
            state,
        })
    }
    fn require_selected(&self) -> Result<(), Error> {
        if matches!(
            self.state,
            PivAccessState::Selected
                | PivAccessState::PinVerified
                | PivAccessState::ManagementAuthorized
                | PivAccessState::PinAndManagementAuthorized
        ) {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::SecurityStatusNotSatisfied))
        }
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

/// Read key, PIN, PUK, or management metadata without SELECT or authentication.
pub fn get_metadata_in_context(
    context: &PivAccessContext,
    reference: MetadataReference,
    options: OperationOptions,
) -> Result<Operation<Metadata>, Error> {
    context.require_selected()?;
    let sequence = super::metadata::prepare_get_metadata(&context.profile, reference, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Read and decode a certificate without SELECT or authentication.
pub fn read_certificate_in_context(
    context: &PivAccessContext,
    slot: Slot,
    options: OperationOptions,
) -> Result<Operation<Certificate>, Error> {
    context.require_selected()?;
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
pub fn read_object_in_context(
    context: &PivAccessContext,
    id: ObjectId,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    context.require_selected()?;
    let sequence = super::prepare_read_object_with(&context.profile, id, options, Ok)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Read the PIV metadata directory in the caller's selected transaction.
pub fn read_metadata_directory_in_context(
    context: &PivAccessContext,
    options: OperationOptions,
) -> Result<Operation<super::MetadataDirectory>, Error> {
    context.require_selected()?;
    let sequence = super::directory::prepare_directory(&context.profile, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Read a persisted container name in the caller's selected transaction.
pub fn read_container_name_in_context(
    context: &PivAccessContext,
    slot: Slot,
    options: OperationOptions,
) -> Result<Operation<super::ContainerName>, Error> {
    context.require_selected()?;
    let sequence = super::configuration::prepare_read_name(&context.profile, slot, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Write a PIV data object after management authorization in the current transaction.
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
pub fn authenticate_management_in_context(
    context: &PivAccessContext,
    auth: ManagementAuthentication,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    context.require_selected()?;
    auth.validate(&context.profile, options)?;
    super::access::in_context(&context.profile, ManagementMachine::new(auth), options)
}

/// Sign using the caller's existing PIV selection and authorization boundary.
/// PIN policy is intentionally enforced by the caller after metadata discovery;
/// this operation never performs an implicit VERIFY or management login.
pub fn sign_in_context(
    context: &PivAccessContext,
    slot: Slot,
    algorithm: Algorithm,
    input: SignInput,
    options: OperationOptions,
) -> Result<Operation<Signature>, Error> {
    context.require_selected()?;
    let sequence = super::private::prepare_sign(&context.profile, slot, algorithm, input, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Sign a complete ML-DSA, Ed25519, or SM2 message using the caller's selected
/// transaction. This operation never performs implicit authentication.
pub fn sign_streaming_in_context(
    context: &PivAccessContext,
    slot: Slot,
    input: StreamingSignInput,
    options: OperationOptions,
) -> Result<Operation<Signature>, Error> {
    context.require_selected()?;
    let machine = super::streaming::prepare_sign_streaming(&context.profile, slot, input, options)?;
    super::access::in_context(&context.profile, machine, options)
}

/// Perform a raw RSA private operation in the caller's selected transaction.
pub fn decrypt_in_context(
    context: &PivAccessContext,
    slot: Slot,
    algorithm: Algorithm,
    ciphertext: SecretBytes,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    context.require_selected()?;
    let sequence =
        super::private::prepare_decrypt(&context.profile, slot, algorithm, ciphertext, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Derive an unprocessed ECDH/X25519 secret in the caller's selected transaction.
pub fn derive_in_context(
    context: &PivAccessContext,
    slot: Slot,
    algorithm: Algorithm,
    peer: Vec<u8>,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    context.require_selected()?;
    let sequence =
        super::private::prepare_derive(&context.profile, slot, algorithm, peer, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}

/// Decapsulate an ML-KEM-768 ciphertext in the caller's selected transaction.
pub fn decapsulate_in_context(
    context: &PivAccessContext,
    slot: Slot,
    ciphertext: SecretBytes,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    context.require_selected()?;
    let sequence =
        super::private::prepare_decapsulate(&context.profile, slot, ciphertext, options)?;
    super::operation_from_sequence(&context.profile, sequence, options)
}
