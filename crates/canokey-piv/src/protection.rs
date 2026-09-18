//! Host-managed PIV ADMIN DATA and PIN-protected PRINTED representations.
use canokey_protocol::{
    tlv::{TlvLimits, TlvReader},
    Error, ErrorKind, Phase, SecretBytes,
};

fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)
}
fn single(data: &[u8], expected: u32) -> Result<&[u8], Error> {
    let mut reader = TlvReader::new_ber(
        data,
        TlvLimits {
            max_value_bytes: 128,
            max_depth: 4,
        },
    );
    let field = reader
        .next()
        .map_err(|e| e.at(Phase::Parsing))?
        .ok_or_else(invalid)?;
    if field.tag.value() != expected || reader.next().map_err(|e| e.at(Phase::Parsing))?.is_some() {
        return Err(invalid());
    }
    Ok(field.value)
}

/// Validated stored management-protection flags; these are claims, not proof of
/// live authentication or of the actual PUK retry counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagementProtection {
    flags: u8,
}
impl ManagementProtection {
    /// Parse complete ADMIN DATA: 53 { 80 { 81 flags, optional 82 salt/83 date } }.
    /// An empty 53 or 80 is valid unconfigured data. Preserve unknown flag bits;
    /// reject duplicate/unknown fields, wrong lengths and trailing bytes.
    /// Salt is empty or 16 bytes; date is at most 8 bytes for legacy compatibility.
    /// No input is retained and no credential is read or changed.
    ///
    /// # Errors
    /// More than 128 input bytes returns LimitExceeded; malformed BER/schema
    /// returns InvalidResponse. Both report Parsing, never unconfigured success.
    pub fn from_admin_object(data: &[u8]) -> Result<Self, Error> {
        if data.len() > 128 {
            return Err(Error::new(ErrorKind::LimitExceeded).at(Phase::Parsing));
        }
        let outer = single(data, 0x53)?;
        if outer.is_empty() {
            return Ok(Self { flags: 0 });
        }
        let admin = single(outer, 0x80)?;
        if admin.is_empty() {
            return Ok(Self { flags: 0 });
        }
        let mut reader = TlvReader::new_ber(
            admin,
            TlvLimits {
                max_value_bytes: 128,
                max_depth: 4,
            },
        );
        let (mut flags, mut salt, mut date) = (None, false, false);
        while let Some(field) = reader.next().map_err(|e| e.at(Phase::Parsing))? {
            match field.tag.value() {
                0x81 if flags.is_none() && field.value.len() == 1 => flags = Some(field.value[0]),
                0x82 if !salt && matches!(field.value.len(), 0 | 16) => salt = true,
                0x83 if !date && field.value.len() <= 8 => date = true,
                _ => return Err(invalid()),
            }
        }
        Ok(Self {
            flags: flags.ok_or_else(invalid)?,
        })
    }
    /// Return observed flags, using zero only for an empty policy container.
    pub fn flags(self) -> u8 {
        self.flags
    }
    /// Whether the stored data claims a blocked PUK. Verify live retries separately.
    pub fn claims_blocked_puk(self) -> bool {
        self.flags & 1 != 0
    }
    /// Whether the stored data enables PIN-protected management-key retrieval.
    pub fn protects_management_key(self) -> bool {
        self.flags & 2 != 0
    }
}

/// Decode complete PRINTED data: 53 { 88 { 89 <24-byte management key> } }.
/// The returned owned bytes are redacted and zeroized; this does not authenticate
/// the key, select its cipher, or prove that ADMIN DATA enables its use.
///
/// # Errors
/// More than 64 input bytes returns LimitExceeded. Missing/duplicate/trailing
/// fields, malformed BER and any key length other than 24 return InvalidResponse.
/// All failures report Parsing; output is created only after complete validation.
pub fn protected_management_key_from_object(data: &[u8]) -> Result<SecretBytes, Error> {
    if data.len() > 64 {
        return Err(Error::new(ErrorKind::LimitExceeded).at(Phase::Parsing));
    }
    let key = single(single(single(data, 0x53)?, 0x88)?, 0x89)?;
    if key.len() != 24 {
        return Err(invalid());
    }
    Ok(SecretBytes::new(key.to_vec()))
}

use crate::{
    access, command, management::ManagementMachine, metadata, Access, DeviceProfile,
    ManagementAuthentication, ManagementKey, ManagementKeyAlgorithm, MetadataReference, ObjectId,
    Operation, OperationOptions,
};
use crate::{Action, Machine, ResponseData};
use canokey_protocol::SecretReference;

/// Check and authenticate PIN-managed management protection in one selected transaction.
/// `block_puk=None` requires an already blocked PUK. `Some` explicitly authorizes
/// irreversible PUK blocking and supplies eight caller-generated random bytes for
/// a temporary replacement if an attempted old PUK happens to match. Authentication
/// of the recovered management key completes before any PUK mutation.
///
/// Access must provide the user PIN or reuse a transaction where it was verified.
/// Returns the verified, owned 24-byte management key for the caller's protected
/// credential cache. The result is redacted/zeroized; no host login state is owned.
/// ADMIN DATA must claim both PIN protection and PUK blocking in either mode.
///
/// # Errors
/// Missing/unconfigured protection is NotFound; inconsistent live PUK state is
/// ConditionsNotSatisfied. Malformed data, unknown management algorithms, auth
/// failures and uncertain transport outcomes stop immediately. At most 32 explicit
/// PUK attempts are sent; failure/drop never restores retries or replays a mutation.
pub fn pin_managed(
    profile: &DeviceProfile,
    block_puk: Option<SecretBytes>,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    crate::require(profile)?;
    profile
        .capability(canokey_compat::Capability::Metadata)
        .require()?;
    let replacement = match block_puk {
        Some(bytes) if bytes.len() == 8 => Some(SecretBytes::new(
            bytes.as_bytes().iter().map(|b| b'0' + b % 10).collect(),
        )),
        Some(_) => return Err(Error::new(ErrorKind::InvalidArgument)),
        None => None,
    };
    let target = PinManaged {
        stage: Stage::Begin,
        profile: profile.clone(),
        options,
        replacement,
        key: None,
        authentication: None,
        attempts: 0,
        known: false,
    };
    access::with_access(profile, access, target, options)
}
#[derive(Clone, Copy)]
enum Stage {
    Begin,
    Admin,
    Puk,
    Printed,
    ManagementMetadata,
    Authentication,
    Change,
    Confirm,
}
struct PinManaged {
    stage: Stage,
    profile: DeviceProfile,
    options: OperationOptions,
    replacement: Option<SecretBytes>,
    key: Option<SecretBytes>,
    authentication: Option<ManagementMachine>,
    attempts: u8,
    known: bool,
}
impl PinManaged {
    fn metadata(
        &self,
        response: ResponseData,
        reference: MetadataReference,
    ) -> Result<metadata::Metadata, Error> {
        response.ensure_success(Phase::Command)?;
        metadata::decode(
            &self.profile,
            reference,
            response.data,
            self.options.limits.max_total_response_bytes,
        )
    }
    fn result(&mut self) -> Result<Action<SecretBytes>, Error> {
        Ok(Action::Done(self.key.take().ok_or_else(invalid)?))
    }
    fn change(&mut self) -> Result<Action<SecretBytes>, Error> {
        if self.attempts >= 32 {
            return Err(Error::new(ErrorKind::ConditionsNotSatisfied).at(Phase::Command));
        }
        let replacement = self.replacement.as_ref().ok_or_else(invalid)?;
        let old = if self.known {
            let mut bytes = replacement.as_bytes().to_vec();
            bytes[0] = if bytes[0] == b'9' { b'0' } else { bytes[0] + 1 };
            SecretBytes::new(bytes)
        } else {
            // Distinct guesses are explicit only in this destructive operation.
            let value = format!("{:08}", self.attempts);
            SecretBytes::new(value.into_bytes())
        };
        self.attempts += 1;
        self.stage = Stage::Change;
        Ok(Action::Command(command::change(
            0x24,
            0x81,
            &old,
            replacement,
        )))
    }
}
impl Machine<SecretBytes> for PinManaged {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<SecretBytes>, Error> {
        if matches!(self.stage, Stage::Begin) {
            self.stage = Stage::Admin;
            return Ok(Action::Command(command::get_data(ObjectId::from_bytes(
                &[0x5f, 0xff, 0],
            )?)));
        }
        if matches!(self.stage, Stage::Authentication) {
            match self
                .authentication
                .as_mut()
                .ok_or_else(invalid)?
                .next(response)?
            {
                Action::Command(c) => return Ok(Action::Command(c)),
                Action::Done(()) => {
                    self.authentication = None;
                    return if self.replacement.is_some() {
                        self.change()
                    } else {
                        self.result()
                    };
                }
            }
        }
        let response = response.ok_or_else(invalid)?;
        match self.stage {
            Stage::Admin => {
                response.ensure_success(Phase::Command)?;
                let policy = ManagementProtection::from_admin_object(response.data.as_bytes())?;
                if !policy.claims_blocked_puk() || !policy.protects_management_key() {
                    return Err(Error::new(ErrorKind::NotFound).at(Phase::Parsing));
                }
                self.stage = Stage::Puk;
                Ok(Action::Command(command::metadata(MetadataReference::Puk)))
            }
            Stage::Puk | Stage::Confirm => {
                let metadata = self.metadata(response, MetadataReference::Puk)?;
                let (_, remaining) = metadata.fields().retries.ok_or_else(invalid)?;
                if matches!(self.stage, Stage::Confirm) {
                    if remaining != 0 {
                        return Err(
                            Error::new(ErrorKind::ConditionsNotSatisfied).at(Phase::Command)
                        );
                    }
                    return self.result();
                }
                if remaining == 0 {
                    self.replacement = None;
                } else if self.replacement.is_none() {
                    return Err(Error::new(ErrorKind::ConditionsNotSatisfied).at(Phase::Command));
                }
                self.stage = Stage::Printed;
                Ok(Action::Command(command::get_data(ObjectId::from_bytes(
                    &[0x5f, 0xc1, 9],
                )?)))
            }
            Stage::Printed => {
                response.ensure_success(Phase::Command)?;
                self.key = Some(protected_management_key_from_object(
                    response.data.as_bytes(),
                )?);
                self.stage = Stage::ManagementMetadata;
                Ok(Action::Command(command::metadata(
                    MetadataReference::Management,
                )))
            }
            Stage::ManagementMetadata => {
                let algorithm = match response.status.raw() {
                    0x6d00 | 0x6a81 | 0x6a88 | 0x6a82 => ManagementKeyAlgorithm::Tdes,
                    _ => match self
                        .metadata(response, MetadataReference::Management)?
                        .fields()
                        .algorithm_id
                    {
                        Some(3) => ManagementKeyAlgorithm::Tdes,
                        Some(10) => ManagementKeyAlgorithm::Aes192,
                        _ => return Err(Error::new(ErrorKind::UnsupportedAlgorithm)),
                    },
                };
                let key = ManagementKey::from_bytes(
                    algorithm,
                    self.key.as_ref().ok_or_else(invalid)?.as_bytes(),
                )?;
                let auth = ManagementAuthentication::external(key);
                auth.validate(&self.profile, self.options)?;
                self.authentication = Some(ManagementMachine::new(auth));
                self.stage = Stage::Authentication;
                self.next(None)
            }
            Stage::Change => {
                if !response.data.is_empty() {
                    return Err(invalid());
                }
                match response.status.raw() {
                    0x9000 => self.known = true,
                    0x6983 | 0x63c0 => {
                        self.stage = Stage::Confirm;
                        return Ok(Action::Command(command::metadata(MetadataReference::Puk)));
                    }
                    sw if sw & 0xfff0 == 0x63c0 => {}
                    _ => {
                        crate::require_auth(&response, SecretReference::Puk)?;
                    }
                }
                self.change()
            }
            _ => Err(Error::new(ErrorKind::OperationStateError)),
        }
    }
}
