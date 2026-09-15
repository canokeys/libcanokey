//! Explicit public probes in an already selected PIV transaction.
use crate::*;
use canokey_compat::AlgorithmConfig;
use canokey_protocol::{ApduHeader, ExpectedLength};

pub(crate) fn single<T: 'static>(
    command: LogicalCommand,
    phase: Phase,
    options: OperationOptions,
    parse: impl FnOnce(ResponseData) -> Result<T, Error> + Send + 'static,
) -> Result<Operation<T>, Error> {
    let options = options.validate()?;
    canokey_protocol::operation::validate_command(&command, options)?;
    Operation::from_machine(
        super::Sequence {
            pending: vec![super::request(command, phase, None)].into(),
            current: None,
            parse: Some(Box::new(parse)),
        },
        options,
    )
}
fn version(response: &ResponseData) -> Result<[u8; 3], Error> {
    response.ensure_success(Phase::Command)?;
    response
        .data
        .as_bytes()
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing))
}
/// Read the selected PIV application's three-byte compatibility version.
/// No profile, SELECT or authentication is inferred; callers choose this probe.
/// # Errors
/// Invalid options fail at construction. Card failures retain Command phase;
/// any successful response other than exactly three bytes is InvalidResponse.
pub fn read_version_selected(options: OperationOptions) -> Result<Operation<SecretBytes>, Error> {
    single(command::version(), Phase::Command, options, |response| {
        version(&response)?;
        Ok(response.data)
    })
}
/// Read algorithm configuration from selected PIV without SELECT/authentication.
/// The caller must establish probe eligibility; observed bytes are preserved and
/// this does not mutate an existing profile or authorize an algorithm.
/// # Errors
/// Invalid options/limits fail at construction; card/security errors remain
/// terminal. Malformed configuration returns InvalidResponse during Parsing.
pub fn read_configuration_selected(
    options: OperationOptions,
) -> Result<Operation<AlgorithmConfig>, Error> {
    single(
        command::algorithm_config(),
        Phase::Command,
        options,
        |response| {
            response.ensure_success(Phase::Command)?;
            AlgorithmConfig::parse(response.data.as_bytes()).map_err(|e| e.at(Phase::Parsing))
        },
    )
}
struct RandomMachine {
    remaining: usize,
    chunk: usize,
    pending: usize,
    version_read: bool,
    started: bool,
    bytes: SecretBytes,
}
impl Machine<SecretBytes> for RandomMachine {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<SecretBytes>, Error> {
        if !self.started {
            self.started = true;
            return Ok(Action::Command(command::version()));
        }
        let response = response.ok_or_else(|| Error::new(ErrorKind::OperationStateError))?;
        if !self.version_read {
            if version(&response)?[0] < 6 {
                return Err(Error::new(ErrorKind::UnsupportedFeature).at(Phase::Command));
            }
            self.version_read = true;
        } else {
            response.ensure_success(Phase::Command)?;
            if response.data.len() != self.pending {
                return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing));
            }
            self.bytes.extend(response.data.as_bytes());
            self.remaining -= self.pending;
        }
        if self.remaining == 0 {
            return Ok(Action::Done(std::mem::take(&mut self.bytes)));
        }
        self.pending = self.remaining.min(self.chunk);
        Ok(Action::Command(LogicalCommand::new(
            ApduHeader::new(0, 0x84, 0, 0),
            vec![],
            ExpectedLength::Exact(self.pending as u32),
        )))
    }
}
/// Read token randomness while retaining the caller's selected transaction.
/// GET VERSION must report PIV 6+ before any RNG command. Commands use at most
/// 256 response bytes, no hidden authentication or retry, and own zeroizing output.
/// A zero-length request still checks the version but sends no RNG command.
/// # Errors
/// Requested output plus version bytes must fit the response budget before any
/// allocation/I/O. Old/unavailable PIV versions return UnsupportedFeature; other
/// status, transport, malformed-length and exchange-budget failures are terminal.
pub fn random_selected(
    length: usize,
    options: OperationOptions,
) -> Result<Operation<SecretBytes>, Error> {
    let options = options.validate()?;
    if length
        .checked_add(3)
        .is_none_or(|n| n > options.limits.max_total_response_bytes)
    {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    let chunk = 256.min(options.exchange.max_response_bytes - 2);
    if length
        .div_ceil(chunk)
        .checked_add(1)
        .is_none_or(|n| n > options.limits.max_exchanges)
    {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    Operation::from_machine(
        RandomMachine {
            remaining: length,
            chunk,
            pending: 0,
            version_read: false,
            started: false,
            bytes: SecretBytes::default(),
        },
        options,
    )
}
