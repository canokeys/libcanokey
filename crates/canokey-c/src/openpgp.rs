use super::*;
use canokey::openpgp as pgp;
/// Explicit OpenPGP verification descriptor, copied before construction returns.
#[repr(C)]
pub struct CnkOpenPgpAccess {
    /// Supported descriptor size.
    pub struct_size: u32,
    /// Wire password reference: 81 PW1-sign, 82 PW1-other, 83 PW3.
    pub reference: u32,
    /// Readable password span, six through 64 bytes (PW3 at least eight).
    pub password: CnkBytes,
}
/// OpenPGP request descriptor; zero unused fields. See the C header for the
/// request/field matrix and WRITE_DATA subtypes. Input spans are copied.
#[repr(C)]
pub struct CnkOpenPgpRequest {
    /// Supported descriptor size.
    pub struct_size: u32,
    /// CNK_OPENPGP_* request kind, 1..20.
    pub kind: u32,
    /// Key slot: 1 signature, 2 decryption, 3 authentication, when applicable.
    pub slot: u32,
    /// Password reference for PIN_STATUS/LOGOUT/CHANGE_PASSWORD.
    pub reference: u32,
    /// READ_DATA complete tag or WRITE_DATA subtype 1..13.
    pub tag: u32,
    /// Semantic CNK_ALGORITHM_* for private operations/import/algorithm writes.
    pub algorithm: u32,
    /// WRITE_DATA scalar: sex/reuse/touch/cache/time; otherwise zero.
    pub value: u32,
    /// Primary input: data, certificate, old password/reset code, or new PW1.
    pub data: CnkBytes,
    /// New password for CHANGE_PASSWORD/UNBLOCK_CODE only.
    pub new_password: CnkBytes,
    /// IMPORT_KEY: six RSA spans e,p,q,qInv,dP,dQ or one EC scalar/seed span.
    pub components: *const CnkBytes,
    /// Number of import components.
    pub component_count: usize,
}
fn reference(r: u32) -> Result<pgp::PasswordReference, u32> {
    match r {
        0x81 => Ok(pgp::PasswordReference::Pw1Sign),
        0x82 => Ok(pgp::PasswordReference::Pw1Other),
        0x83 => Ok(pgp::PasswordReference::Pw3),
        _ => Err(ARG),
    }
}
fn slot(s: u32) -> Result<pgp::Slot, u32> {
    match s {
        1 => Ok(pgp::Slot::Signature),
        2 => Ok(pgp::Slot::Decryption),
        3 => Ok(pgp::Slot::Authentication),
        _ => Err(ARG),
    }
}
unsafe fn span(s: &CnkBytes) -> Result<&[u8], u32> {
    bytes(s.data, s.len)
}
unsafe fn password(s: &CnkBytes) -> Result<pgp::Password, u32> {
    pgp::Password::from_bytes(span(s)?).map_err(|_| ARG)
}
unsafe fn data_write(d: &CnkOpenPgpRequest) -> Result<pgp::DataWrite, u32> {
    use pgp::DataWrite as W;
    if (!matches!(d.tag, 8 | 10..=13) && d.slot != 0)
        || (d.tag != 10 && d.algorithm != 0)
        || (!matches!(d.tag, 4 | 7..=9 | 13) && d.value != 0)
        || (matches!(d.tag, 4 | 7..=10 | 13) && (!d.data.data.is_null() || d.data.len != 0))
    {
        return Err(ARG);
    }
    Ok(match d.tag {
        1 => W::Name(span(&d.data)?.to_vec()),
        2 => W::Login(SecretBytes::new(span(&d.data)?.to_vec())),
        3 => W::Language(span(&d.data)?.to_vec()),
        4 => W::Sex(d.value.try_into().map_err(|_| ARG)?),
        5 => W::Url(span(&d.data)?.to_vec()),
        6 => W::ResetCode(if d.data.len == 0 {
            None
        } else {
            Some(password(&d.data)?)
        }),
        7 if d.value <= 1 => W::ReuseSignaturePin(d.value != 0),
        8 => W::TouchPolicy(
            slot(d.slot)?,
            match d.value {
                0 => pgp::TouchPolicy::Off,
                1 => pgp::TouchPolicy::On,
                2 => pgp::TouchPolicy::Permanent,
                _ => return Err(ARG),
            },
        ),
        9 => W::TouchCacheTime(d.value.try_into().map_err(|_| ARG)?),
        10 => W::Algorithm(slot(d.slot)?, piv_keys::algorithm(d.algorithm)?),
        11 => W::Fingerprint(slot(d.slot)?, span(&d.data)?.try_into().map_err(|_| ARG)?),
        12 => W::CaFingerprint(slot(d.slot)?, span(&d.data)?.try_into().map_err(|_| ARG)?),
        13 => W::GenerationTime(slot(d.slot)?, d.value),
        _ => return Err(ARG),
    })
}
unsafe fn request(d: &CnkOpenPgpRequest) -> Result<pgp::Request, u32> {
    if d.struct_size < std::mem::size_of::<CnkOpenPgpRequest>() as u32
        || (!matches!(d.kind, 2 | 3 | 11..=14) && d.slot != 0)
        || (!matches!(d.kind, 4 | 6 | 7) && d.reference != 0)
        || (!matches!(d.kind, 1 | 11) && d.tag != 0)
        || (!matches!(d.kind, 11 | 14..=18) && d.algorithm != 0)
        || (d.kind != 11 && d.value != 0)
        || (!matches!(d.kind,3|7..=11|15..=18) && (!d.data.data.is_null() || d.data.len != 0))
        || (!matches!(d.kind, 7 | 9) && (!d.new_password.data.is_null() || d.new_password.len != 0))
        || (d.kind != 14 && (!d.components.is_null() || d.component_count != 0))
    {
        return Err(ARG);
    }
    use pgp::Request as R;
    let input = || span(&d.data).map(|b| SecretBytes::new(b.to_vec()));
    Ok(match d.kind {
        1 => R::ReadData(d.tag.try_into().map_err(|_| ARG)?),
        2 => R::ReadCertificate(slot(d.slot)?),
        3 => R::WriteCertificate(slot(d.slot)?, input()?),
        4 => R::PinStatus(reference(d.reference)?),
        5 => R::Verify,
        6 => R::Logout(reference(d.reference)?),
        7 => R::ChangePassword {
            reference: reference(d.reference)?,
            old: password(&d.data)?,
            new: password(&d.new_password)?,
        },
        8 => R::UnblockWithAdmin(password(&d.data)?),
        9 => R::UnblockWithCode {
            code: password(&d.data)?,
            new: password(&d.new_password)?,
        },
        10 => R::ResetRetries(span(&d.data)?.try_into().map_err(|_| ARG)?),
        11 => R::WriteData(data_write(d)?),
        12 => R::ReadPublicKey(slot(d.slot)?),
        13 => R::GenerateKey(slot(d.slot)?),
        14 => {
            let algorithm = piv_keys::algorithm(d.algorithm)?;
            let rsa = matches!(
                algorithm,
                pgp::Algorithm::Rsa2048 | pgp::Algorithm::Rsa3072 | pgp::Algorithm::Rsa4096
            );
            if d.components.is_null() || d.component_count != if rsa { 6 } else { 1 } {
                return Err(ARG);
            }
            let parts = slice::from_raw_parts(d.components, d.component_count);
            if parts.iter().any(|p| p.len > 256) {
                return Err(ARG);
            }
            let secret = |i: usize| span(&parts[i]).map(|b| SecretBytes::new(b.to_vec()));
            let key = if rsa {
                pgp::PrivateKey::Rsa {
                    exponent: span(&parts[0])?.try_into().map_err(|_| ARG)?,
                    p: secret(1)?,
                    q: secret(2)?,
                    q_inverse: secret(3)?,
                    d_p: secret(4)?,
                    d_q: secret(5)?,
                }
            } else {
                pgp::PrivateKey::Ec(secret(0)?)
            };
            R::ImportKey {
                slot: slot(d.slot)?,
                algorithm,
                key,
            }
        }
        15 => R::Sign(piv_keys::algorithm(d.algorithm)?, input()?),
        16 => R::Authenticate(piv_keys::algorithm(d.algorithm)?, input()?),
        17 => R::Decrypt(piv_keys::algorithm(d.algorithm)?, input()?),
        18 => R::Derive(piv_keys::algorithm(d.algorithm)?, span(&d.data)?.to_vec()),
        19 => R::Terminate,
        20 => R::Activate,
        _ => return Err(ARG),
    })
}
/// Construct an OpenPGP operation, copying request, credentials and all spans.
///
/// # Safety
/// Follow the crate pointer contract. profile/descriptor must be live non-NULL;
/// auth is optional, nested spans readable, out writable/non-NULL and optional
/// options/error versioned. The returned operation is caller-owned.
#[no_mangle]
pub unsafe extern "C" fn cnk_openpgp_new(
    profile: *const CnkProfile,
    descriptor: *const CnkOpenPgpRequest,
    auth: *const CnkOpenPgpAccess,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let request = request(descriptor.as_ref().ok_or(ARG)?)?;
        let access = if let Some(a) = auth.as_ref() {
            if a.struct_size < std::mem::size_of::<CnkOpenPgpAccess>() as u32 {
                return Err(ARG);
            }
            Some(pgp::Access {
                reference: reference(a.reference)?,
                password: password(&a.password)?,
            })
        } else {
            None
        };
        pgp::operation(
            &profile.as_ref().ok_or(ARG)?.0,
            request,
            access,
            options(opts)?,
        )
        .map(Inner::OpenPgp)
        .map_err(|e| failure(e, error))
    })
}
/// Copy OpenPGP result subtype: 1 bytes, 2 unit, 3 PIN status, 4 public key,
/// 5 signature. Existing byte, public-key, algorithm and PIN getters apply.
///
/// # Safety
/// Follow the crate pointer contract. op must be live without concurrent mutation;
/// out must be writable/non-NULL and not alias the operation.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_openpgp_kind(op: *const CnkOperation, out: *mut u32) -> u32 {
    guard(|| {
        if out.is_null() {
            return ARG;
        }
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        let Inner::OpenPgp(p) = &op.inner else {
            return TYPE;
        };
        let Ok(v) = p.result() else {
            return STATE;
        };
        *out = match v {
            pgp::Outcome::Bytes(_) => 1,
            pgp::Outcome::Unit => 2,
            pgp::Outcome::PinStatus(_) => 3,
            pgp::Outcome::PublicKey(_) => 4,
            pgp::Outcome::Signature { .. } => 5,
        };
        OK
    })
}
