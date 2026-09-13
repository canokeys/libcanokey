//! Copied Batch request arrays and indexed results, without additional handles.
use super::*;
use piv_keys::{algorithm, material, parameters};
use piv_mutation::{management, slot};

/// Copied semantic Batch request. Only fields associated with kind are read.
/// Unused spans/pointers should be NULL/zero. No request is an operation handle.
#[repr(C)]
pub struct CnkBatchRequest {
    /// Supported prefix size in bytes.
    pub struct_size: u32,
    /// CNK_BATCH_* semantic request kind.
    pub kind: u32,
    /// Slot/metadata reference when applicable.
    pub reference: u32,
    /// CNK_ALGORITHM_* for private operations; CNK_MANAGEMENT_* for key replacement.
    pub algorithm: u32,
    /// CNK_SIGN_* for signing; CNK_MANAGEMENT_TOUCH_* for management-key replacement.
    pub input_kind: u32,
    /// PIN, object value, certificate payload, signing input, ciphertext or peer bytes.
    pub data: *const u8,
    /// Payload length.
    pub data_len: usize,
    /// Object tag bytes for object reads/writes; otherwise NULL.
    pub tag: *const u8,
    /// Object tag length.
    pub tag_len: usize,
    /// Management descriptor for explicit authentication; otherwise NULL.
    pub management: *const CnkManagement,
    /// Key generation/import parameters; otherwise NULL.
    pub parameters: *const CnkKeyParameters,
    /// Import components; otherwise NULL.
    pub components: *const CnkBytes,
    /// Number of import components.
    pub component_count: usize,
}
/// Construct a Batch by copying all requests and nested inputs before returning.
/// Management authentication must be an earlier explicit request for mutations.
/// # Safety
/// Follow the crate pointer/aliasing contract. profile must be live/non-NULL;
/// requests must cover count descriptors with valid nested ranges. out must be
/// writable/non-NULL; optional opts/error must be valid versioned structs.
#[no_mangle]
pub unsafe extern "C" fn cnk_piv_batch_new(
    profile: *const CnkProfile,
    requests: *const CnkBatchRequest,
    count: usize,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        if requests.is_null() || count == 0 || count > piv::batch::MAX_BATCH_REQUESTS {
            return Err(ARG);
        }
        let options = options(opts)?;
        let requests = slice::from_raw_parts(requests, count);
        let mut total = 0usize;
        for request in requests {
            if request.struct_size < std::mem::size_of::<CnkBatchRequest>() as u32 {
                return Err(ARG);
            }
            total = total.checked_add(request.data_len).ok_or(ARG)?;
        }
        if total > options.limits.max_input_bytes {
            return Err(failure(Error::new(ErrorKind::LimitExceeded), error));
        }
        let mut owned = Vec::with_capacity(count);
        for r in requests {
            let data = || bytes(r.data, r.data_len).map(|v| SecretBytes::new(v.to_vec()));
            let id = || {
                piv::ObjectId::from_bytes(bytes(r.tag, r.tag_len)?).map_err(|e| failure(e, error))
            };
            let request = match r.kind {
                1 => piv::BatchRequest::VerifyPin(
                    piv::Pin::from_bytes(bytes(r.data, r.data_len)?)
                        .map_err(|e| failure(e, error))?,
                ),
                2 => piv::BatchRequest::AuthenticateManagement(management(r.management, error)?),
                3 => piv::BatchRequest::Logout,
                4 => piv::BatchRequest::ReadObject(id()?),
                5 => piv::BatchRequest::ReadCertificate(slot(r.reference)?),
                6 => piv::BatchRequest::WriteObject {
                    id: id()?,
                    data: data()?,
                },
                7 => piv::BatchRequest::WriteCertificate {
                    slot: slot(r.reference)?,
                    der: data()?,
                },
                8 => piv::BatchRequest::DeleteCertificate(slot(r.reference)?),
                9 => piv::BatchRequest::GetMetadata(match r.reference {
                    0x80 => piv::MetadataReference::Pin,
                    0x81 => piv::MetadataReference::Puk,
                    0x9b => piv::MetadataReference::Management,
                    n => piv::MetadataReference::Key(slot(n)?),
                }),
                10 => piv::BatchRequest::ReadAlgorithmConfig,
                11 => piv::BatchRequest::GenerateKey(parameters(r.parameters)?),
                12 => {
                    let p = parameters(r.parameters)?;
                    piv::BatchRequest::ImportKey {
                        parameters: p,
                        material: material(p.algorithm, r.components, r.component_count, error)?,
                    }
                }
                13 => piv::BatchRequest::Sign {
                    slot: slot(r.reference)?,
                    algorithm: algorithm(r.algorithm)?,
                    input: match r.input_kind {
                        1 => piv::SignInput::RsaEncodedBlock(data()?),
                        2 => piv::SignInput::Digest(data()?),
                        3 => piv::SignInput::Message(data()?),
                        _ => return Err(ARG),
                    },
                },
                14 => piv::BatchRequest::Decrypt {
                    slot: slot(r.reference)?,
                    algorithm: algorithm(r.algorithm)?,
                    ciphertext: data()?,
                },
                15 => piv::BatchRequest::Derive {
                    slot: slot(r.reference)?,
                    algorithm: algorithm(r.algorithm)?,
                    peer: bytes(r.data, r.data_len)?.to_vec(),
                },
                16 => piv::BatchRequest::SetManagementKey {
                    key: piv::ManagementKey::from_bytes(
                        match r.algorithm {
                            1 => piv::ManagementKeyAlgorithm::Tdes,
                            2 => piv::ManagementKeyAlgorithm::Aes192,
                            _ => return Err(ARG),
                        },
                        bytes(r.data, r.data_len)?,
                    )
                    .map_err(|e| failure(e, error))?,
                    touch: match r.input_kind {
                        0 => piv::ManagementTouchPolicy::Never,
                        1 => piv::ManagementTouchPolicy::Always,
                        _ => return Err(ARG),
                    },
                },
                17 => piv::BatchRequest::Decapsulate {
                    slot: slot(r.reference)?,
                    ciphertext: data()?,
                },
                _ => return Err(ARG),
            };
            owned.push(request);
        }
        piv::batch(&profile.as_ref().ok_or(ARG)?.0, owned, options)
            .map(Inner::Batch)
            .map_err(|e| failure(e, error))
    })
}
/// Caller-owned completed count and optional failure index for a Batch.
#[repr(C)]
pub struct CnkBatchProgress {
    /// Supported prefix size in bytes.
    pub struct_size: u32,
    /// Successful requests, including explicit authentication items.
    pub completed_count: u32,
    /// One when failed_index is present, zero otherwise.
    pub has_failed_index: u32,
    /// Zero-based failed request index when present.
    pub failed_index: u32,
}
unsafe fn results<'a>(op: *const CnkOperation) -> Result<&'a piv::BatchResults, u32> {
    let op = op.as_ref().ok_or(ARG)?;
    if op.poisoned {
        return Err(STATE);
    }
    let Inner::Batch(inner) = &op.inner else {
        return Err(TYPE);
    };
    piv::batch_progress(inner).ok_or(STATE)
}
/// Copy progress during execution/failure/completion. Before requests begin or
/// after cancellation/result transfer, return INVALID_STATE. No device access occurs.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_batch_progress(
    op: *const CnkOperation,
    out: *mut CnkBatchProgress,
) -> u32 {
    guard(|| {
        if out.is_null() || (*out).struct_size < std::mem::size_of::<CnkBatchProgress>() as u32 {
            return ARG;
        }
        match results(op) {
            Ok(r) => {
                (*out).completed_count = r.items().len() as u32;
                (*out).has_failed_index = u32::from(r.failed_index().is_some());
                (*out).failed_index = r.failed_index().unwrap_or(0) as u32;
                OK
            }
            Err(code) => code,
        }
    })
}
/// Copy the CNK_RESULT_* kind of a successful Batch item, by zero-based index.
/// Out-of-range indices return INVALID_ARGUMENT; unfinished items are not exposed.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL and not alias the operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_batch_item_kind(
    op: *const CnkOperation,
    index: usize,
    out: *mut u32,
) -> u32 {
    guard(|| {
        if out.is_null() {
            return ARG;
        }
        let r = match results(op) {
            Ok(r) => r,
            Err(c) => return c,
        };
        let Some(item) = r.items().get(index) else {
            return ARG;
        };
        *out = match item {
            piv::BatchItem::Unit => 2,
            piv::BatchItem::Bytes(_) => 4,
            piv::BatchItem::Certificate(_) => 5,
            piv::BatchItem::Mutation(_) => 6,
            piv::BatchItem::Metadata(_) => 7,
            piv::BatchItem::PublicKey(_) => 8,
            piv::BatchItem::Signature(_) => 9,
            piv::BatchItem::AlgorithmConfig(_) => 10,
        };
        OK
    })
}
/// Copy completed Batch bytes by index: raw secret/object, certificate payload,
/// signature, metadata TLV or algorithm configuration. Public keys return DER SPKI.
/// Unit/mutation items return RESULT_TYPE_MISMATCH. Uses query-size/copy semantics.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; len must be initialized/writable/non-NULL. Non-NULL buffer must
/// cover the incoming *len writable bytes and not overlap len or the operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_batch_item_copy_bytes(
    op: *const CnkOperation,
    index: usize,
    buffer: *mut u8,
    len: *mut usize,
) -> u32 {
    guard(|| {
        let r = match results(op) {
            Ok(r) => r,
            Err(c) => return c,
        };
        let Some(item) = r.items().get(index) else {
            return ARG;
        };
        match item {
            piv::BatchItem::Bytes(b) => copy(b.as_bytes(), buffer, len),
            piv::BatchItem::Certificate(c) => copy(c.der(), buffer, len),
            piv::BatchItem::Metadata(m) => copy(m.fields().raw.as_bytes(), buffer, len),
            piv::BatchItem::AlgorithmConfig(c) => copy(c.raw(), buffer, len),
            piv::BatchItem::Signature(s) => copy(s.as_bytes(), buffer, len),
            piv::BatchItem::PublicKey(k) => match k.to_spki_der() {
                Ok(der) => copy(&der, buffer, len),
                Err(_) => PROTOCOL,
            },
            _ => TYPE,
        }
    })
}
/// Copy the profile effect of a successful mutation item without another handle.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_batch_item_mutation(
    op: *const CnkOperation,
    index: usize,
    out: *mut CnkMutationResult,
) -> u32 {
    guard(|| {
        if out.is_null() || (*out).struct_size < std::mem::size_of::<CnkMutationResult>() as u32 {
            return ARG;
        }
        let r = match results(op) {
            Ok(r) => r,
            Err(c) => return c,
        };
        let Some(item) = r.items().get(index) else {
            return ARG;
        };
        let piv::BatchItem::Mutation(m) = item else {
            return TYPE;
        };
        (*out).profile_effect = match m.profile_effect {
            piv::ProfileEffect::Unchanged => 0,
            piv::ProfileEffect::ReprobeRequired => 1,
        };
        OK
    })
}

/// Copy typed scalar metadata from a completed Batch item.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_batch_item_metadata(
    op: *const CnkOperation,
    index: usize,
    out: *mut CnkMetadata,
) -> u32 {
    guard(|| {
        let r = match results(op) {
            Ok(r) => r,
            Err(c) => return c,
        };
        match r.items().get(index) {
            Some(piv::BatchItem::Metadata(m)) => piv_keys::copy_metadata(m, out),
            Some(_) => TYPE,
            None => ARG,
        }
    })
}
/// Copy a public-key component or DER SPKI from a generated-key/metadata Batch item.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; len must be initialized/writable/non-NULL. Non-NULL buffer must
/// cover the incoming *len bytes and not overlap len or the operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_batch_item_public_key_copy(
    op: *const CnkOperation,
    index: usize,
    field: u32,
    buffer: *mut u8,
    len: *mut usize,
) -> u32 {
    guard(|| {
        let r = match results(op) {
            Ok(r) => r,
            Err(c) => return c,
        };
        let key = match r.items().get(index) {
            Some(piv::BatchItem::PublicKey(k)) => k,
            Some(piv::BatchItem::Metadata(m)) => match m.fields().public_key.as_ref() {
                Some(k) => k,
                None => return TYPE,
            },
            Some(_) => return TYPE,
            None => return ARG,
        };
        piv_keys::copy_public_key(key, field, buffer, len)
    })
}
/// Copy an EC Batch signature as fixed-width P1363 r || s.
/// # Safety
/// Follow the crate pointer/aliasing contract. op must be live without concurrent
/// mutation/free; len must be initialized/writable/non-NULL. Non-NULL buffer must
/// cover the incoming *len writable bytes and not overlap len or the operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_batch_item_signature_p1363(
    op: *const CnkOperation,
    index: usize,
    buffer: *mut u8,
    len: *mut usize,
) -> u32 {
    guard(|| {
        let r = match results(op) {
            Ok(r) => r,
            Err(c) => return c,
        };
        match r.items().get(index) {
            Some(piv::BatchItem::Signature(s)) => match s.to_p1363() {
                Ok(bytes) => copy(&bytes, buffer, len),
                Err(_) => TYPE,
            },
            Some(_) => TYPE,
            None => ARG,
        }
    })
}
