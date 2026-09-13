//! Explicit semantic requests executed under one SELECT, without rollback/replay.
use crate::*;
use canokey_compat::AlgorithmConfig;

/// Maximum semantic requests in one batch, independently of physical exchange limits.
pub const MAX_BATCH_REQUESTS: usize = 128;
/// Owned semantic request, without implicit Access or nested operation handles.
/// Authenticate explicitly before mutations; repeat VERIFY before PIN-always uses.
#[derive(Debug)]
pub enum BatchRequest {
    /// SM2 agreement with pre-exchanged peer inputs.
    AgreeSm2 {
        /// Key-management/retired slot.
        slot: Slot,
        /// Owned peer keys, role and identities.
        input: Sm2AgreementInput,
    },
    /// Read the compact key/certificate directory.
    ReadMetadataDirectory,
    /// Read a slot's UTF-16 container name.
    ReadContainerName(Slot),
    /// Set/clear a name after explicit management authentication.
    SetContainerName {
        /// Ordinary asymmetric slot.
        slot: Slot,
        /// Owned validated name; empty clears it.
        name: ContainerName,
    },
    /// Move only a key/name, leaving certificates in place.
    MoveKey {
        /// Existing key slot.
        source: Slot,
        /// Empty destination slot.
        target: Slot,
    },
    /// Delete only a key and its name, leaving its certificate in place.
    DeleteKey(Slot),
    /// Reset PIN/PUK to defaults with retry limits. Requires preceding management
    /// authentication and an immediately preceding VerifyPin request. Clears auth.
    ResetPinPukRetries {
        /// PIN retry limit, 1..=15.
        pin_retries: u8,
        /// PUK retry limit, 1..=15.
        puk_retries: u8,
    },
    /// Replace algorithm IDs; must be the final request, since the profile becomes stale.
    SetAlgorithmConfig(AlgorithmConfig),
    /// Obtain an attestation certificate as opaque DER bytes.
    Attest(Slot),
    /// Explicit PIN verification.
    VerifyPin(Pin),
    /// Explicit External/Mutual management authentication, with owned fresh inputs.
    AuthenticateManagement(ManagementAuthentication),
    /// Clear the PIN verification state; does not release a connection.
    Logout,
    /// Read a normalized object value.
    ReadObject(ObjectId),
    /// Read and unwrap a certificate.
    ReadCertificate(Slot),
    /// Write a normalized object value (excluding 53).
    WriteObject {
        /// Object identifier.
        id: ObjectId,
        /// Owned bytes.
        data: ObjectData,
    },
    /// Write a nonempty certificate payload with library-owned 70/71/FE framing.
    WriteCertificate {
        /// Certificate slot.
        slot: Slot,
        /// Uncompressed payload, without X.509 validation.
        der: SecretBytes,
    },
    /// Delete a certificate on evidenced firmware, without deleting its key.
    DeleteCertificate(Slot),
    /// Replace the management key after an explicit authentication request.
    SetManagementKey {
        /// Replacement key.
        key: ManagementKey,
        /// Replacement touch policy.
        touch: ManagementTouchPolicy,
    },
    /// Read an individual metadata record.
    GetMetadata(MetadataReference),
    /// Read the observed algorithm configuration.
    ReadAlgorithmConfig,
    /// Generate a key with explicit parameters; requires prior management authentication.
    GenerateKey(KeyParameters),
    /// Import typed key material; requires prior management authentication.
    ImportKey {
        /// Slot, algorithm and policy choices.
        parameters: KeyParameters,
        /// Owned secret components.
        material: PrivateKeyMaterial,
    },
    /// Classic signing; hashing/padding remain caller choices.
    Sign {
        /// Signing slot.
        slot: Slot,
        /// Key algorithm.
        algorithm: Algorithm,
        /// Owned input.
        input: SignInput,
    },
    /// Explicit full-message streaming signing with an owned mode and message.
    SignStreaming {
        /// Asymmetric slot.
        slot: Slot,
        /// Full message and explicit firmware mode.
        input: StreamingSignInput,
    },
    /// Raw RSA decryption without unpadding.
    Decrypt {
        /// Key-management/retired slot.
        slot: Slot,
        /// RSA algorithm.
        algorithm: Algorithm,
        /// Modulus-sized input.
        ciphertext: SecretBytes,
    },
    /// Raw ECDH/X25519 agreement without a KDF.
    Derive {
        /// Key-management/retired slot.
        slot: Slot,
        /// Agreement algorithm.
        algorithm: Algorithm,
        /// Public peer encoding.
        peer: Vec<u8>,
    },
    /// ML-KEM-768 decapsulation without a KDF or sender authentication.
    Decapsulate {
        /// Key-management/retired slot.
        slot: Slot,
        /// Exactly 1088 ciphertext bytes.
        ciphertext: SecretBytes,
    },
}
impl BatchRequest {
    fn input_len(&self) -> usize {
        match self {
            Self::AgreeSm2 { input, .. } => input.input_len(),
            Self::SetContainerName { name, .. } => name.as_utf16le().len(),
            Self::SetAlgorithmConfig(config) => config.raw().len(),
            Self::VerifyPin(pin) => pin.0.len(),
            Self::AuthenticateManagement(auth) => auth.input_len(),
            Self::WriteObject { data, .. } => data.len(),
            Self::WriteCertificate { der, .. } => der.len(),
            Self::SetManagementKey { .. } => 24,
            Self::ImportKey { material, .. } => material.input_len(),
            Self::Sign { input, .. } => match input {
                SignInput::RsaEncodedBlock(b) | SignInput::Digest(b) | SignInput::Message(b) => {
                    b.len()
                }
            },
            Self::Decrypt { ciphertext, .. } | Self::Decapsulate { ciphertext, .. } => {
                ciphertext.len()
            }
            Self::SignStreaming { input, .. } => input.input_len(),
            Self::Derive { peer, .. } => peer.len(),
            _ => 0,
        }
    }
}
/// One completed request's owned result; order matches the request list.
#[derive(Debug)]
pub enum BatchItem {
    /// SM2 derived key and own public ephemeral point.
    Sm2Agreement(Sm2Agreement),
    /// Compact directory observation, including entry diagnostics.
    Directory(MetadataDirectory),
    /// Validated per-slot container name.
    ContainerName(ContainerName),
    /// Authentication/logout completed.
    Unit,
    /// Normalized object or raw private-operation bytes, redacted and wiped on drop.
    Bytes(SecretBytes),
    /// Unwrapped certificate.
    Certificate(Certificate),
    /// Successful mutation; caches remain caller-owned.
    Mutation(MutationResult),
    /// Metadata observation.
    Metadata(Metadata),
    /// Observed algorithm configuration.
    AlgorithmConfig(AlgorithmConfig),
    /// Generated public key.
    PublicKey(PublicKey),
    /// Algorithm-tagged signature.
    Signature(Signature),
}
impl BatchItem {
    fn byte_len(&self) -> usize {
        match self {
            Self::Sm2Agreement(a) => a.key.len() + a.ephemeral_public.len(),
            Self::Directory(d) => d.raw().len(),
            Self::ContainerName(n) => n.as_utf16le().len(),
            Self::Unit | Self::Mutation(_) => 0,
            Self::Bytes(b) => b.len(),
            Self::Certificate(c) => c.der().len(),
            Self::Metadata(m) => m.fields().raw.len(),
            Self::AlgorithmConfig(c) => c.raw().len(),
            Self::Signature(s) => s.as_bytes().len(),
            Self::PublicKey(PublicKey::Rsa {
                modulus, exponent, ..
            }) => modulus.len() + exponent.len(),
            Self::PublicKey(PublicKey::Ec { point, .. }) => point.len(),
            Self::PublicKey(PublicKey::Raw { bytes, .. }) => bytes.len(),
        }
    }
}
/// Completed items and failure location. No unfinished request's secrets are exposed.
#[derive(Debug, Default)]
pub struct BatchResults {
    items: Vec<BatchItem>,
    failed_index: Option<usize>,
}
impl BatchResults {
    /// Borrow successful preceding items in request order. Includes explicit auth items.
    pub fn items(&self) -> &[BatchItem] {
        &self.items
    }
    /// Zero-based failed request index after an error; None while running/successful.
    /// Selection failure has no request index and no retained batch progress.
    pub fn failed_index(&self) -> Option<usize> {
        self.failed_index
    }
    /// Transfer the completed items independently of an operation.
    pub fn into_items(self) -> Vec<BatchItem> {
        self.items
    }
}
/// Borrow completed items while running, after failure or after completion.
/// Returns None before the batch starts its first request, after SELECT failure,
/// cancellation or result transfer. Getters never issue commands or consume results.
pub fn batch_progress(operation: &Operation<BatchResults>) -> Option<&BatchResults> {
    operation.result().ok().or_else(|| operation.progress())
}
struct Mapped<T, M> {
    inner: M,
    convert: fn(T) -> BatchItem,
}
impl<T, M: Machine<T>> Machine<BatchItem> for Mapped<T, M> {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<BatchItem>, Error> {
        match self.inner.next(response)? {
            Action::Command(c) => Ok(Action::Command(c)),
            Action::Done(value) => Ok(Action::Done((self.convert)(value))),
        }
    }
}
fn mapped<T: 'static>(
    machine: impl Machine<T> + 'static,
    convert: fn(T) -> BatchItem,
) -> Box<dyn Machine<BatchItem>> {
    Box::new(Mapped {
        inner: machine,
        convert,
    })
}
struct BatchMachine {
    pending: VecDeque<Box<dyn Machine<BatchItem>>>,
    current: Option<Box<dyn Machine<BatchItem>>>,
    results: BatchResults,
    result_bytes: usize,
    max_result_bytes: usize,
}
impl Machine<BatchResults> for BatchMachine {
    fn next(&mut self, mut response: Option<ResponseData>) -> Result<Action<BatchResults>, Error> {
        loop {
            if self.current.is_none() {
                self.current = self.pending.pop_front();
            }
            let Some(current) = self.current.as_mut() else {
                return Ok(Action::Done(std::mem::take(&mut self.results)));
            };
            match current.next(response.take())? {
                Action::Command(command) => return Ok(Action::Command(command)),
                Action::Done(value) => {
                    self.result_bytes = self
                        .result_bytes
                        .checked_add(value.byte_len())
                        .ok_or_else(|| Error::new(ErrorKind::LimitExceeded))?;
                    if self.result_bytes > self.max_result_bytes {
                        return Err(Error::new(ErrorKind::LimitExceeded).at(Phase::Parsing));
                    }
                    self.results.items.push(value);
                    self.current = None;
                }
            }
        }
    }
    fn progress(&self) -> Option<&BatchResults> {
        Some(&self.results)
    }
    fn take_progress(&mut self) -> Option<BatchResults> {
        if self.current.is_some() {
            self.results.failed_index = Some(self.results.items.len());
        }
        Some(std::mem::take(&mut self.results))
    }
}
/// Construct one operation for explicit requests under a single SELECT.
/// All requests are checked and their input ownership transferred before execution.
/// Management authentication must precede each sequence of mutations; it is never
/// inserted implicitly. Requests have no Access and cannot contain SELECT, probe
/// or another Batch. Successful items survive a later error through batch_progress.
///
/// # Errors
/// Empty/oversized lists, aggregate semantic inputs above max_input_bytes, missing
/// explicit management authentication, unsupported requests and channel budgets
/// fail before SELECT. The first execution failure stops the batch and retains its
/// original typed error. Completed count is items().len(); no rollback/replay occurs.
pub fn batch(
    profile: &DeviceProfile,
    requests: Vec<BatchRequest>,
    options: OperationOptions,
) -> Result<Operation<BatchResults>, Error> {
    require(profile)?;
    options.validate()?;
    if requests.is_empty() || requests.len() > MAX_BATCH_REQUESTS {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    let mut input_bytes = 0usize;
    for r in &requests {
        input_bytes = input_bytes
            .checked_add(r.input_len())
            .ok_or_else(|| Error::new(ErrorKind::LimitExceeded))?;
    }
    if input_bytes > options.limits.max_input_bytes {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let mut pending = VecDeque::new();
    let mut management = false;
    let mut previous_verify = false;
    let count = requests.len();
    for (index, request) in requests.into_iter().enumerate() {
        if matches!(request, BatchRequest::ResetPinPukRetries { .. }) && !previous_verify {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        if matches!(request, BatchRequest::SetAlgorithmConfig(_)) && index + 1 != count {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        previous_verify = matches!(request, BatchRequest::VerifyPin(_));
        if matches!(
            request,
            BatchRequest::SetContainerName { .. }
                | BatchRequest::MoveKey { .. }
                | BatchRequest::DeleteKey(_)
                | BatchRequest::ResetPinPukRetries { .. }
                | BatchRequest::SetAlgorithmConfig(_)
                | BatchRequest::WriteObject { .. }
                | BatchRequest::WriteCertificate { .. }
                | BatchRequest::DeleteCertificate(_)
                | BatchRequest::SetManagementKey { .. }
                | BatchRequest::GenerateKey(_)
                | BatchRequest::ImportKey { .. }
        ) && !management
        {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        let machine = match request {
            BatchRequest::AgreeSm2 { slot, input } => mapped(
                sm2_agreement::prepare_agreement(profile, slot, input, options)?,
                BatchItem::Sm2Agreement,
            ),
            BatchRequest::ReadMetadataDirectory => mapped(
                directory::prepare_directory(profile, options)?,
                BatchItem::Directory,
            ),
            BatchRequest::ReadContainerName(slot) => mapped(
                configuration::prepare_read_name(profile, slot, options)?,
                BatchItem::ContainerName,
            ),
            BatchRequest::SetContainerName { slot, name } => mapped(
                configuration::prepare_set_name(profile, slot, name, options)?,
                BatchItem::Mutation,
            ),
            BatchRequest::MoveKey { source, target } => mapped(
                configuration::prepare_move_delete(profile, source, Some(target), options)?,
                BatchItem::Mutation,
            ),
            BatchRequest::DeleteKey(slot) => mapped(
                configuration::prepare_move_delete(profile, slot, None, options)?,
                BatchItem::Mutation,
            ),
            BatchRequest::ResetPinPukRetries {
                pin_retries,
                puk_retries,
            } => {
                management = false;
                mapped(
                    configuration::prepare_retry_reset(profile, pin_retries, puk_retries, options)?,
                    BatchItem::Mutation,
                )
            }
            BatchRequest::SetAlgorithmConfig(config) => mapped(
                configuration::prepare_config(profile, config, options)?,
                BatchItem::Mutation,
            ),
            BatchRequest::Attest(slot) => mapped(
                configuration::prepare_attest(profile, slot, options)?,
                BatchItem::Bytes,
            ),
            BatchRequest::VerifyPin(pin) => mapped(
                access::prepare(command::verify_pin(&pin), options, |r| {
                    require_auth(&r, SecretReference::Pin)?;
                    if !r.data.is_empty() {
                        return Err(
                            Error::new(ErrorKind::InvalidResponse).at(Phase::Authentication)
                        );
                    }
                    Ok(())
                })?,
                |()| BatchItem::Unit,
            ),
            BatchRequest::AuthenticateManagement(auth) => {
                auth.validate(profile, options)?;
                management = true;
                mapped(management::ManagementMachine::new(auth), |()| {
                    BatchItem::Unit
                })
            }
            BatchRequest::Logout => mapped(
                access::prepare(command::logout(), options, |r| {
                    r.ensure_success(Phase::Authentication)
                })?,
                |()| BatchItem::Unit,
            ),
            BatchRequest::ReadObject(id) => mapped(
                prepare_read_object_with(profile, id, options, Ok)?,
                BatchItem::Bytes,
            ),
            BatchRequest::ReadCertificate(slot) => mapped(
                prepare_read_object_with(
                    profile,
                    ObjectId::certificate(slot),
                    options,
                    move |data| {
                        Certificate::from_object(
                            data.as_bytes(),
                            options.limits.max_total_response_bytes,
                        )
                    },
                )?,
                BatchItem::Certificate,
            ),
            BatchRequest::WriteObject { id, data } => mapped(
                write::prepare_write_object(profile, id, data, options)?,
                BatchItem::Mutation,
            ),
            BatchRequest::WriteCertificate { slot, der } => mapped(
                write::prepare_write_certificate(profile, slot, der, options)?,
                BatchItem::Mutation,
            ),
            BatchRequest::DeleteCertificate(slot) => mapped(
                write::prepare_delete_certificate(profile, slot, options)?,
                BatchItem::Mutation,
            ),
            BatchRequest::SetManagementKey { key, touch } => mapped(
                write::prepare_set_management_key(profile, key, touch, options)?,
                BatchItem::Mutation,
            ),
            BatchRequest::GetMetadata(reference) => mapped(
                metadata::prepare_get_metadata(profile, reference, options)?,
                BatchItem::Metadata,
            ),
            BatchRequest::ReadAlgorithmConfig => mapped(
                metadata::prepare_read_algorithm_config(profile, options)?,
                BatchItem::AlgorithmConfig,
            ),
            BatchRequest::GenerateKey(parameters) => mapped(
                keys::prepare_generate_key(profile, parameters, options)?,
                BatchItem::PublicKey,
            ),
            BatchRequest::ImportKey {
                parameters,
                material,
            } => mapped(
                keys::prepare_import_key(profile, parameters, material, options)?,
                BatchItem::Mutation,
            ),
            BatchRequest::Sign {
                slot,
                algorithm,
                input,
            } => mapped(
                private::prepare_sign(profile, slot, algorithm, input, options)?,
                BatchItem::Signature,
            ),
            BatchRequest::SignStreaming { slot, input } => mapped(
                streaming::prepare_sign_streaming(profile, slot, input, options)?,
                BatchItem::Signature,
            ),
            BatchRequest::Decrypt {
                slot,
                algorithm,
                ciphertext,
            } => mapped(
                private::prepare_decrypt(profile, slot, algorithm, ciphertext, options)?,
                BatchItem::Bytes,
            ),
            BatchRequest::Derive {
                slot,
                algorithm,
                peer,
            } => mapped(
                private::prepare_derive(profile, slot, algorithm, peer, options)?,
                BatchItem::Bytes,
            ),
            BatchRequest::Decapsulate { slot, ciphertext } => mapped(
                private::prepare_decapsulate(profile, slot, ciphertext, options)?,
                BatchItem::Bytes,
            ),
        };
        pending.push_back(machine);
    }
    access::with_access(
        profile,
        Access::None,
        BatchMachine {
            pending,
            current: None,
            results: BatchResults::default(),
            result_bytes: 0,
            max_result_bytes: options.limits.max_total_response_bytes,
        },
        options,
    )
}
