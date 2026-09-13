use super::*;
use canokey::oath;
/// Copied OATH descriptor. Zero-initialize unused fields.
#[repr(C)]
pub struct CnkOathRequest {
    /// Supported descriptor size.
    pub struct_size: u32,
    /// 1 SELECT, 2 VALIDATE, 3 LIST, 4 PUT, 5 DELETE, 6 RENAME,
    /// 7 CALCULATE, 8 CALCULATE_ALL, 9 SET_CODE, 10 CLEAR_CODE.
    pub kind: u32,
    /// Credential name for PUT/DELETE/RENAME/CALCULATE.
    pub name: *const u8,
    /// Name byte count.
    pub name_len: usize,
    /// New name for RENAME.
    pub new_name: *const u8,
    /// New name byte count.
    pub new_name_len: usize,
    /// PUT credential secret or SET_CODE new sixteen-byte access key.
    pub secret: *const u8,
    /// Secret byte count.
    pub secret_len: usize,
    /// Optional current sixteen-byte access key; NULL/zero means none.
    pub access_key: *const u8,
    /// Access key byte count.
    pub access_key_len: usize,
    /// Fresh eight-byte host challenge, required with access_key.
    pub host_challenge: *const u8,
    /// Host challenge byte count.
    pub host_challenge_len: usize,
    /// Eight-byte TOTP challenge, or fresh SET_CODE challenge.
    pub challenge: *const u8,
    /// Challenge byte count; zero for HOTP.
    pub challenge_len: usize,
    /// PUT/CALCULATE: 1 HOTP, 2 TOTP.
    pub credential_kind: u32,
    /// PUT/CALCULATE: 1 SHA1, 2 SHA256, 3 SHA512.
    pub algorithm: u32,
    /// PUT: four through eight digits.
    pub digits: u32,
    /// PUT: bit 0 increasing, bit 1 require touch. Other bits rejected.
    pub properties: u32,
    /// PUT: initial HOTP counter; first pinned-firmware use calculates N+1.
    pub initial_counter: u32,
    /// CALCULATE/CALCULATE_ALL: 1 truncated, 2 full.
    pub format: u32,
}
fn algorithm(value: u32) -> Result<oath::Algorithm, u32> {
    match value {
        1 => Ok(oath::Algorithm::Sha1),
        2 => Ok(oath::Algorithm::Sha256),
        3 => Ok(oath::Algorithm::Sha512),
        _ => Err(ARG),
    }
}
fn kind(value: u32) -> Result<oath::Kind, u32> {
    match value {
        1 => Ok(oath::Kind::Hotp),
        2 => Ok(oath::Kind::Totp),
        _ => Err(ARG),
    }
}
fn format(value: u32) -> Result<oath::Format, u32> {
    match value {
        1 => Ok(oath::Format::Truncated),
        2 => Ok(oath::Format::Full),
        _ => Err(ARG),
    }
}
unsafe fn request(d: &CnkOathRequest) -> Result<oath::Request, u32> {
    if d.struct_size < std::mem::size_of::<CnkOathRequest>() as u32
        || (!matches!(d.kind, 4..=7) && (!d.name.is_null() || d.name_len != 0))
        || (d.kind != 6 && (!d.new_name.is_null() || d.new_name_len != 0))
        || (!matches!(d.kind, 4 | 9) && (!d.secret.is_null() || d.secret_len != 0))
        || (!matches!(d.kind, 7..=9) && (!d.challenge.is_null() || d.challenge_len != 0))
        || (!matches!(d.kind, 4 | 7) && (d.credential_kind != 0 || d.algorithm != 0))
        || (d.kind != 4 && (d.digits != 0 || d.properties != 0 || d.initial_counter != 0))
        || (!matches!(d.kind, 7 | 8) && d.format != 0)
    {
        return Err(ARG);
    }
    let name = || oath::Name::from_bytes(bytes(d.name, d.name_len)?).map_err(|_| ARG);
    let challenge = || {
        bytes(d.challenge, d.challenge_len)?
            .try_into()
            .map_err(|_| ARG)
    };
    use oath::Request as R;
    Ok(match d.kind {
        1 => R::Select,
        2 => R::Validate,
        3 => R::List,
        4 => {
            if d.properties & !3 != 0 {
                return Err(ARG);
            }
            R::Put(oath::Credential {
                name: name()?,
                kind: kind(d.credential_kind)?,
                algorithm: algorithm(d.algorithm)?,
                digits: d.digits.try_into().map_err(|_| ARG)?,
                secret: SecretBytes::new(bytes(d.secret, d.secret_len)?.to_vec()),
                increasing: d.properties & 1 != 0,
                require_touch: d.properties & 2 != 0,
                initial_counter: d.initial_counter,
            })
        }
        5 => R::Delete(name()?),
        6 => R::Rename {
            old: name()?,
            new: oath::Name::from_bytes(bytes(d.new_name, d.new_name_len)?).map_err(|_| ARG)?,
        },
        7 => R::Calculate {
            name: name()?,
            kind: kind(d.credential_kind)?,
            algorithm: algorithm(d.algorithm)?,
            challenge: if d.challenge.is_null() && d.challenge_len == 0 {
                None
            } else {
                Some(challenge()?)
            },
            format: format(d.format)?,
        },
        8 => R::CalculateAll {
            challenge: challenge()?,
            format: format(d.format)?,
        },
        9 => R::SetCode {
            key: oath::AccessKey::from_bytes(bytes(d.secret, d.secret_len)?).map_err(|_| ARG)?,
            challenge: challenge()?,
        },
        10 => R::ClearCode,
        _ => return Err(ARG),
    })
}
/// Construct an OATH operation, copying all input spans. No transport or global state.
///
/// # Safety
/// Follow the crate pointer contract; profile/descriptor must be live non-NULL,
/// spans readable and out writable/non-NULL. Optional options/error are versioned.
#[no_mangle]
pub unsafe extern "C" fn cnk_oath_new(
    profile: *const CnkProfile,
    descriptor: *const CnkOathRequest,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let d = descriptor.as_ref().ok_or(ARG)?;
        let request = request(d)?;
        let access = if d.access_key.is_null() && d.access_key_len == 0 {
            if !d.host_challenge.is_null() || d.host_challenge_len != 0 {
                return Err(ARG);
            }
            None
        } else {
            Some(oath::Access {
                key: oath::AccessKey::from_bytes(bytes(d.access_key, d.access_key_len)?)
                    .map_err(|e| failure(e, error))?,
                challenge: bytes(d.host_challenge, d.host_challenge_len)?
                    .try_into()
                    .map_err(|_| ARG)?,
            })
        };
        oath::operation(
            &profile.as_ref().ok_or(ARG)?.0,
            request,
            access,
            options(opts)?,
        )
        .map(Inner::Oath)
        .map_err(|e| failure(e, error))
    })
}
/// OATH result header or indexed item metadata; initialize struct_size.
#[repr(C)]
pub struct CnkOathInfo {
    /// Supported structure size.
    pub struct_size: u32,
    /// 1 selection, 2 entries, 3 calculations, 4 unit.
    pub kind: u32,
    /// Number of list/calculation items; zero for other outcomes.
    pub count: usize,
    /// Entry raw algorithm/type byte, or SELECT access algorithm (0 if absent).
    pub algorithm_type: u32,
    /// Calculation digit count.
    pub digits: u32,
    /// 1 truncated, 2 full, 3 HOTP marker, 4 touch marker; zero for other outcomes.
    pub code_kind: u32,
    /// SELECT: bit 0 challenge present. Calculation: bit 0 name present.
    pub flags: u32,
    /// SELECT version observation; zero for other outcomes.
    pub version: [u8; 3],
    /// Reserved output, always zero.
    pub reserved: u8,
    /// SELECT device handle; zero for other outcomes.
    pub handle: [u8; 8],
    /// SELECT challenge when present; zero otherwise.
    pub challenge: [u8; 8],
}
/// Copy OATH metadata. Entries/calculations require a valid index; others index zero.
///
/// # Safety
/// Follow the crate pointer contract. op must be live without concurrent mutation;
/// out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_oath_info(
    op: *const CnkOperation,
    index: usize,
    out: *mut CnkOathInfo,
) -> u32 {
    guard(|| {
        if out.is_null() || (*out).struct_size < std::mem::size_of::<CnkOathInfo>() as u32 {
            return ARG;
        }
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        let Inner::Oath(p) = &op.inner else {
            return TYPE;
        };
        let Ok(v) = p.result() else {
            return STATE;
        };
        let mut info = CnkOathInfo {
            struct_size: (*out).struct_size,
            kind: 0,
            count: 0,
            algorithm_type: 0,
            digits: 0,
            code_kind: 0,
            flags: 0,
            version: [0; 3],
            reserved: 0,
            handle: [0; 8],
            challenge: [0; 8],
        };
        use oath::Outcome;
        match v {
            Outcome::Selection(s) if index == 0 => {
                info.kind = 1;
                info.algorithm_type = s.algorithm.unwrap_or(0).into();
                info.flags = u32::from(s.challenge.is_some());
                info.version = s.version;
                info.handle = s.handle;
                info.challenge = s.challenge.unwrap_or([0; 8]);
            }
            Outcome::Entries(entries) => {
                info.kind = 2;
                info.count = entries.len();
                if let Some(e) = entries.get(index) {
                    info.algorithm_type = e.algorithm_type.into();
                } else if index != 0 || !entries.is_empty() {
                    return ARG;
                }
            }
            Outcome::Calculations(codes) => {
                info.kind = 3;
                info.count = codes.len();
                if let Some(c) = codes.get(index) {
                    info.digits = c.digits.into();
                    info.flags = u32::from(c.name.is_some());
                    info.code_kind = match c.code {
                        oath::Code::Truncated(_) => 1,
                        oath::Code::Full(_) => 2,
                        oath::Code::Hotp => 3,
                        oath::Code::TouchRequired => 4,
                    };
                } else if index != 0 || !codes.is_empty() {
                    return ARG;
                }
            }
            Outcome::Unit if index == 0 => info.kind = 4,
            _ => return ARG,
        }
        ptr::write(out, info);
        OK
    })
}
/// Copy OATH data: field 1 original SELECT bytes, 2 indexed name, 3 indexed code,
/// 4 indexed decimal code. NULL buffer queries size. Markers/full decimal return
/// RESULT_TYPE_MISMATCH. Code copies are secrets and must be wiped by the caller.
///
/// # Safety
/// Follow the crate pointer contract; op live without concurrent mutation, len
/// initialized/writable/non-NULL and buffer covering incoming *len when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_oath_copy(
    op: *const CnkOperation,
    index: usize,
    field: u32,
    buffer: *mut u8,
    len: *mut usize,
) -> u32 {
    guard(|| {
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        let Inner::Oath(p) = &op.inner else {
            return TYPE;
        };
        let Ok(v) = p.result() else {
            return STATE;
        };
        match v {
            oath::Outcome::Selection(s) if index == 0 && field == 1 => {
                copy(s.raw.as_bytes(), buffer, len)
            }
            oath::Outcome::Entries(entries) if field == 2 => match entries.get(index) {
                Some(e) => copy(e.name.as_bytes(), buffer, len),
                None => ARG,
            },
            oath::Outcome::Calculations(codes) => {
                let Some(c) = codes.get(index) else {
                    return ARG;
                };
                match field {
                    2 => match &c.name {
                        Some(n) => copy(n.as_bytes(), buffer, len),
                        None => TYPE,
                    },
                    3 => match &c.code {
                        oath::Code::Truncated(b) | oath::Code::Full(b) => {
                            copy(b.as_bytes(), buffer, len)
                        }
                        _ => TYPE,
                    },
                    4 => match c.decimal() {
                        Some(b) => copy(b.as_bytes(), buffer, len),
                        None => TYPE,
                    },
                    _ => TYPE,
                }
            }
            _ => TYPE,
        }
    })
}
