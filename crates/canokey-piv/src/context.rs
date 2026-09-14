//! Caller-owned PIV transaction contexts.
use crate::{
    Algorithm, Certificate, DeviceProfile, Error, ErrorKind, Metadata, MetadataReference, ObjectId,
    Operation, OperationOptions, SignInput, Signature, Slot, StreamingSignInput,
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
    super::operation_from_machine(machine, options)
}
