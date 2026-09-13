//! Explicit management-key authentication with caller-supplied mutual challenges.
use crate::*;
use aes::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use canokey_protocol::{ApduHeader, ExpectedLength};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use canokey_compat::ManagementKeyAlgorithm;

/// Owned 24-byte management key. Debug is redacted and storage is wiped on drop.
/// This does not store authentication state or imply a device supports its algorithm.
#[derive(Clone, Debug)]
pub struct ManagementKey {
    algorithm: ManagementKeyAlgorithm,
    bytes: SecretBytes,
}
impl ManagementKey {
    /// Copy exactly 24 raw key bytes; return InvalidArgument for any other length.
    /// No default-key substitution or DES parity normalization is performed.
    pub fn from_bytes(algorithm: ManagementKeyAlgorithm, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 24 {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        Ok(Self {
            algorithm,
            bytes: SecretBytes::new(bytes.to_vec()),
        })
    }
    /// Return the selected algorithm without exposing key bytes.
    pub fn algorithm(&self) -> ManagementKeyAlgorithm {
        self.algorithm
    }
    pub(crate) fn replacement_command(&self, touch: bool) -> LogicalCommand {
        let mut data = SecretBytes::new(vec![self.algorithm.wire_id(), 0x9b, 24]);
        data.extend(self.bytes.as_bytes());
        let mut command = LogicalCommand::new(
            ApduHeader::new(0, 0xff, 0xff, if touch { 0xfe } else { 0xff }),
            vec![],
            ExpectedLength::Absent,
        );
        command.data = data;
        command
    }

    fn crypt(&self, input: &[u8], decrypt: bool) -> Result<SecretBytes, Error> {
        // Both cipher schedules implement zeroization on drop. The block must also
        // be protected: it can contain a decrypted witness or host challenge.
        fn block<C: KeyInit + BlockEncrypt + BlockDecrypt + zeroize::ZeroizeOnDrop>(
            key: &[u8],
            input: &[u8],
            decrypt: bool,
        ) -> Result<SecretBytes, Error> {
            let cipher =
                C::new_from_slice(key).map_err(|_| Error::new(ErrorKind::InvalidArgument))?;
            let mut bytes = Zeroizing::new(input.to_vec());
            let block = Block::<C>::from_mut_slice(&mut bytes);
            if decrypt {
                cipher.decrypt_block(block);
            } else {
                cipher.encrypt_block(block);
            }
            Ok(SecretBytes::new(block.to_vec()))
        }
        if input.len() != self.algorithm.block_len() {
            return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Authentication));
        }
        match self.algorithm {
            ManagementKeyAlgorithm::Tdes => {
                block::<des::TdesEde3>(self.bytes.as_bytes(), input, decrypt)
            }
            ManagementKeyAlgorithm::Aes192 => {
                block::<aes::Aes192>(self.bytes.as_bytes(), input, decrypt)
            }
        }
    }
}

#[derive(Clone, Debug)]
enum Mode {
    External,
    Mutual(SecretBytes),
}

/// Owned authentication inputs; no I/O, cached login, or reusable authorization token.
/// Prefer Mutual when the application needs to authenticate the card as well.
/// Cloning a mutual request copies its challenge: callers must not reuse that clone
/// for another execution and must supply fresh randomness for each new operation.
#[derive(Clone, Debug)]
pub struct ManagementAuthentication {
    key: ManagementKey,
    mode: Mode,
}
impl ManagementAuthentication {
    /// Authenticate the host to the card using the card's challenge.
    /// External authentication does not authenticate the card to the host.
    pub fn external(key: ManagementKey) -> Self {
        Self {
            key,
            mode: Mode::External,
        }
    }
    /// Authenticate both parties using a fresh CSPRNG challenge supplied by the caller.
    /// Copies the challenge (8 bytes for 3DES, 16 for AES-192). Invalid length returns
    /// InvalidArgument. Randomness quality and uniqueness cannot be checked here.
    pub fn mutual(key: ManagementKey, challenge: &[u8]) -> Result<Self, Error> {
        if challenge.len() != key.algorithm.block_len() {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        Ok(Self {
            key,
            mode: Mode::Mutual(SecretBytes::new(challenge.to_vec())),
        })
    }
    pub(crate) fn validate(
        &self,
        profile: &DeviceProfile,
        options: OperationOptions,
    ) -> Result<(), Error> {
        profile
            .management_key_support(self.key.algorithm)
            .require()?;
        // Validate both possible commands before SELECT, including channel limits.
        canokey_protocol::operation::validate_command(&self.initial()?, options)?;
        let zeros = [0u8; 16];
        let fields = match &self.mode {
            Mode::External => vec![(0x82, &zeros[..self.key.algorithm.block_len()])],
            Mode::Mutual(challenge) => vec![
                (0x80, &zeros[..self.key.algorithm.block_len()]),
                (0x81, challenge.as_bytes()),
            ],
        };
        canokey_protocol::operation::validate_command(
            &auth_command(self.key.algorithm, &fields)?,
            options,
        )
    }
    fn initial(&self) -> Result<LogicalCommand, Error> {
        auth_command(
            self.key.algorithm,
            &[(
                match self.mode {
                    Mode::External => 0x81,
                    Mode::Mutual(_) => 0x80,
                },
                &[],
            )],
        )
    }
}

fn auth_command(
    algorithm: ManagementKeyAlgorithm,
    fields: &[(u8, &[u8])],
) -> Result<LogicalCommand, Error> {
    let mut inner = canokey_protocol::tlv::TlvWriter::new(36);
    for (tag, value) in fields {
        inner.push(Tag::from_bytes(&[*tag])?, value)?;
    }
    let mut outer = canokey_protocol::tlv::TlvWriter::new(38);
    outer.push(Tag::from_bytes(&[0x7c])?, inner.into_bytes().as_bytes())?;
    let mut command = LogicalCommand::new(
        ApduHeader::new(0, 0x87, algorithm.wire_id(), 0x9b),
        vec![],
        ExpectedLength::Absent,
    );
    command.data = outer.into_bytes();
    Ok(command)
}

fn auth_status(response: &ResponseData) -> Result<(), Error> {
    if response.status.is_success() {
        return Ok(());
    }
    let mut error = auth_error(response.status, SecretReference::ManagementKey);
    if response.status.raw() == 0x6982 {
        error.kind = ErrorKind::AuthenticationFailed;
    }
    Err(error)
}
fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(Phase::Authentication)
}
fn auth_field(data: &[u8], tag: u32, len: usize) -> Result<&[u8], Error> {
    let mut outer = TlvReader::new(
        data,
        TlvLimits {
            max_value_bytes: 18,
            max_depth: 2,
        },
    );
    let wrapped = outer.next()?.ok_or_else(invalid)?;
    if wrapped.tag.value() != 0x7c || outer.next()?.is_some() {
        return Err(invalid());
    }
    let mut inner = wrapped.children()?;
    let field = inner.next()?.ok_or_else(invalid)?;
    if field.tag.value() != tag || field.value.len() != len || inner.next()?.is_some() {
        return Err(invalid());
    }
    Ok(field.value)
}

pub(crate) struct ManagementMachine {
    auth: ManagementAuthentication,
    stage: u8,
}
impl ManagementMachine {
    pub(crate) fn new(auth: ManagementAuthentication) -> Self {
        Self { auth, stage: 0 }
    }
}
impl Machine<()> for ManagementMachine {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<()>, Error> {
        match self.stage {
            0 => {
                self.stage = 1;
                Ok(Action::Command(self.auth.initial()?))
            }
            1 => {
                let response = response.ok_or_else(invalid)?;
                auth_status(&response)?;
                let mutual = matches!(self.auth.mode, Mode::Mutual(_));
                let value = auth_field(
                    response.data.as_bytes(),
                    if mutual { 0x80 } else { 0x81 },
                    self.auth.key.algorithm.block_len(),
                )?;
                let value = self.auth.key.crypt(value, mutual)?;
                let fields = match &self.auth.mode {
                    Mode::External => vec![(0x82, value.as_bytes())],
                    Mode::Mutual(challenge) => {
                        vec![(0x80, value.as_bytes()), (0x81, challenge.as_bytes())]
                    }
                };
                self.stage = 2;
                Ok(Action::Command(auth_command(
                    self.auth.key.algorithm,
                    &fields,
                )?))
            }
            2 => {
                let response = response.ok_or_else(invalid)?;
                auth_status(&response)?;
                match &self.auth.mode {
                    Mode::External if !response.data.is_empty() => return Err(invalid()),
                    Mode::Mutual(challenge) => {
                        let actual = auth_field(
                            response.data.as_bytes(),
                            0x82,
                            self.auth.key.algorithm.block_len(),
                        )?;
                        let expected = self.auth.key.crypt(challenge.as_bytes(), false)?;
                        if !bool::from(expected.as_bytes().ct_eq(actual)) {
                            let mut error = Error::new(ErrorKind::DeviceAuthenticationFailed)
                                .at(Phase::Authentication);
                            error.reference = Some(SecretReference::ManagementKey);
                            return Err(error);
                        }
                    }
                    _ => {}
                }
                self.stage = 3;
                Ok(Action::Done(()))
            }
            _ => Err(Error::new(ErrorKind::OperationStateError)),
        }
    }
}

/// Select PIV and perform one explicit External or Mutual authentication.
/// Owns key/challenge inputs and selects exactly once. Success is not an
/// authorization token for subsequent standalone operations; use Access to
/// authenticate and execute a dependent command together.
///
/// # Errors
/// Unsupported/unknown firmware algorithms fail before SELECT. Malformed replies
/// fail parsing; a wrong mutual cryptogram returns DeviceAuthenticationFailed.
/// Card failures retain the management reference and SW, never PIN retry counts.
/// No fallback, default credentials, or authentication retry is attempted.
pub fn authenticate_management_key(
    profile: &DeviceProfile,
    auth: ManagementAuthentication,
    options: OperationOptions,
) -> Result<Operation<()>, Error> {
    require(profile)?;
    auth.validate(profile, options)?;
    crate::access::with_access(profile, Access::None, ManagementMachine::new(auth), options)
}
