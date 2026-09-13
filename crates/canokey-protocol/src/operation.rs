use crate::{
    ApduEncoding, ApduHeader, CommandApdu, Error, ErrorKind, ExpectedLength, Phase, ResponseApdu,
    SecretBytes, StatusWord,
};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug)]
pub struct ExchangeOptions {
    pub max_command_bytes: usize,
    pub max_response_bytes: usize,
    pub allow_extended: bool,
}
impl Default for ExchangeOptions {
    fn default() -> Self {
        Self {
            max_command_bytes: 261,
            max_response_bytes: 258,
            allow_extended: false,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct OperationLimits {
    pub max_total_response_bytes: usize,
    pub max_exchanges: usize,
    pub max_input_bytes: usize,
}
impl Default for OperationLimits {
    fn default() -> Self {
        Self {
            max_total_response_bytes: 1024 * 1024,
            max_exchanges: 4096,
            max_input_bytes: 1024 * 1024,
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct OperationOptions {
    pub exchange: ExchangeOptions,
    pub limits: OperationLimits,
}
impl OperationOptions {
    pub fn validate(self) -> Result<Self, Error> {
        if self.exchange.max_command_bytes < 5
            || self.exchange.max_response_bytes < 3
            || self.limits.max_exchanges == 0
            || self.limits.max_total_response_bytes == 0
            || self.limits.max_input_bytes == 0
        {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        Ok(self)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Exchange,
    Done,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationState {
    Created,
    AwaitingResponse,
    Completed,
    Failed,
    Cancelled,
    ResultTaken,
}

/// Applet-specific conversation policy. OATH's non-ISO protocol is deliberately
/// not approximated by an ISO GET RESPONSE loop.
#[derive(Clone, Copy, Debug)]
pub enum Continuation {
    Iso7816 { cla: u8 },
    None,
}
#[derive(Clone, Debug)]
pub struct LogicalCommand {
    pub header: ApduHeader,
    pub data: SecretBytes,
    pub le: ExpectedLength,
    pub allow_chaining: bool,
    pub allow_extended: bool,
    pub correct_le: bool,
    pub continuation: Continuation,
}
impl LogicalCommand {
    pub fn new(header: ApduHeader, data: Vec<u8>, le: ExpectedLength) -> Self {
        Self {
            header,
            data: SecretBytes::new(data),
            le,
            allow_chaining: false,
            allow_extended: false,
            correct_le: false,
            continuation: Continuation::Iso7816 { cla: 0 },
        }
    }
}
#[derive(Debug)]
pub struct ResponseData {
    pub data: SecretBytes,
    pub status: StatusWord,
}
impl ResponseData {
    pub fn ensure_success(&self, phase: Phase) -> Result<(), Error> {
        if self.status.is_success() {
            Ok(())
        } else {
            Err(Error::status(self.status, phase, None))
        }
    }
}

/// Implementation interface for the workspace applet crates, not an I/O hook.
/// Applications normally use applet factory functions returning `Operation<T>`.
#[doc(hidden)]
pub mod engine {
    use super::*;
    pub enum Action<T> {
        Command(LogicalCommand),
        Done(T),
    }
    pub trait Machine<T>: Send {
        fn next(&mut self, response: Option<ResponseData>) -> Result<Action<T>, Error>;
    }
}
use engine::{Action, Machine};

struct ConversationState {
    pending: VecDeque<CommandApdu>,
    current: CommandApdu,
    corrected: bool,
    correct_le: bool,
    continuation: Continuation,
    continuing: bool,
    data: SecretBytes,
}
impl ConversationState {
    fn new(mut logical: LogicalCommand, options: OperationOptions) -> Result<Self, Error> {
        if logical.data.len() > options.limits.max_input_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        if matches!(logical.le, ExpectedLength::Exact(n) if n == 0 || n > 65536) {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        if let ExpectedLength::Exact(n) = logical.le {
            if n as usize > options.exchange.max_response_bytes - 2 {
                if matches!(logical.continuation, Continuation::Iso7816 { .. })
                    && logical.correct_le
                {
                    logical.le =
                        ExpectedLength::Exact((options.exchange.max_response_bytes - 2) as u32);
                } else {
                    return Err(Error::new(ErrorKind::LimitExceeded));
                }
            }
        }
        // Reserve space for Le, so any fragment fits even on smaller channels.
        let max_short = options
            .exchange
            .max_command_bytes
            .saturating_sub(6)
            .min(255);
        let mut frames = VecDeque::new();
        let extended = logical.allow_extended && options.exchange.allow_extended;
        if extended && logical.data.len() <= 65535 {
            let cmd = CommandApdu::encode(
                logical.header,
                logical.data.as_bytes(),
                logical.le,
                ApduEncoding::Extended,
            )?;
            if cmd.as_bytes().len() <= options.exchange.max_command_bytes {
                frames.push_back(cmd);
            }
        }
        if frames.is_empty() {
            if matches!(logical.le, ExpectedLength::Exact(n) if n > 256) {
                return Err(Error::new(ErrorKind::LimitExceeded));
            }
            let data = logical.data.as_bytes();
            if data.is_empty() || data.len() <= max_short {
                frames.push_back(CommandApdu::encode(
                    logical.header,
                    data,
                    logical.le,
                    ApduEncoding::Short,
                )?);
            } else {
                if !logical.allow_chaining || max_short == 0 || logical.header.cla & 0x10 != 0 {
                    return Err(Error::new(ErrorKind::LimitExceeded));
                }
                let count = data.len().div_ceil(max_short);
                if count > options.limits.max_exchanges {
                    return Err(Error::new(ErrorKind::LimitExceeded));
                }
                for (i, chunk) in data.chunks(max_short).enumerate() {
                    let last = i + 1 == count;
                    let mut header = logical.header;
                    if !last {
                        header.cla |= 0x10;
                    }
                    frames.push_back(CommandApdu::encode(
                        header,
                        chunk,
                        if last {
                            logical.le
                        } else {
                            ExpectedLength::Absent
                        },
                        ApduEncoding::Short,
                    )?);
                }
            }
        }
        let current = frames
            .pop_front()
            .ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
        if current.as_bytes().len() > options.exchange.max_command_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        Ok(Self {
            current,
            pending: frames,
            corrected: false,
            correct_le: logical.correct_le,
            continuation: logical.continuation,
            continuing: false,
            data: SecretBytes::default(),
        })
    }
    fn advance(
        &mut self,
        response: ResponseApdu<'_>,
        options: OperationOptions,
    ) -> Result<Option<ResponseData>, Error> {
        let sw = response.status().raw();
        if sw >> 8 == 0x6c && self.correct_le && self.pending.is_empty() && !self.corrected {
            let le = if sw & 255 == 0 { 256 } else { sw & 255 } as u32;
            if le as usize > options.exchange.max_response_bytes - 2 {
                return Err(Error::new(ErrorKind::LimitExceeded));
            }
            self.current = self.current.corrected(le)?;
            if self.current.as_bytes().len() > options.exchange.max_command_bytes {
                return Err(Error::new(ErrorKind::LimitExceeded));
            }
            self.corrected = true;
            return Ok(None);
        }
        if !self.pending.is_empty() {
            if !response.status().is_success() {
                return Err(Error::status(response.status(), Phase::Conversation, None));
            }
            if !response.data().is_empty() {
                return Err(Error::new(ErrorKind::ProtocolViolation).at(Phase::Conversation));
            }
            self.current = self
                .pending
                .pop_front()
                .ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
            self.corrected = false;
            return Ok(None);
        }
        self.data.extend(response.data());
        if let Continuation::Iso7816 { cla } = self.continuation {
            if sw >> 8 == 0x61 {
                if self.continuing && response.data().is_empty() {
                    return Err(Error::new(ErrorKind::ProtocolViolation).at(Phase::Conversation));
                }
                self.continuing = true;
                let le = if sw & 255 == 0 {
                    256
                } else {
                    (sw & 255) as usize
                };
                let le = le.min(options.exchange.max_response_bytes - 2) as u32;
                self.current = CommandApdu::encode(
                    ApduHeader::new(cla, 0xc0, 0, 0),
                    &[],
                    ExpectedLength::Exact(le),
                    ApduEncoding::Short,
                )?;
                self.corrected = false;
                self.correct_le = true;
                return Ok(None);
            }
        }
        Ok(Some(ResponseData {
            data: std::mem::take(&mut self.data),
            status: response.status(),
        }))
    }
}

/// An owned protocol operation. All getters are local and never send commands.
pub struct Operation<T> {
    machine: Option<Box<dyn Machine<T>>>,
    conversation: Option<ConversationState>,
    output: Option<T>,
    error: Option<Error>,
    state: OperationState,
    options: OperationOptions,
    exchanges: usize,
    response_bytes: usize,
}
impl<T> std::fmt::Debug for Operation<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operation")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
impl<T> Operation<T> {
    #[doc(hidden)]
    pub fn from_machine(
        machine: impl Machine<T> + 'static,
        options: OperationOptions,
    ) -> Result<Self, Error> {
        Ok(Self {
            machine: Some(Box::new(machine)),
            conversation: None,
            output: None,
            error: None,
            state: OperationState::Created,
            options: options.validate()?,
            exchanges: 0,
            response_bytes: 0,
        })
    }
    pub fn state(&self) -> OperationState {
        self.state
    }
    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }
    pub fn command(&self) -> Result<&CommandApdu, Error> {
        if self.state != OperationState::AwaitingResponse {
            return Err(state_error());
        }
        self.conversation
            .as_ref()
            .map(|c| &c.current)
            .ok_or_else(state_error)
    }
    pub fn result(&self) -> Result<&T, Error> {
        if self.state != OperationState::Completed {
            return Err(state_error());
        }
        self.output.as_ref().ok_or_else(state_error)
    }
    pub fn take_result(&mut self) -> Result<T, Error> {
        if self.state != OperationState::Completed {
            return Err(state_error());
        }
        let value = self.output.take().ok_or_else(state_error)?;
        self.state = OperationState::ResultTaken;
        Ok(value)
    }
    pub fn cancel(&mut self) {
        if matches!(
            self.state,
            OperationState::Created | OperationState::AwaitingResponse
        ) {
            self.machine = None;
            self.conversation = None;
            self.state = OperationState::Cancelled;
        }
    }
    pub fn start(&mut self) -> Result<Step, Error> {
        if self.state != OperationState::Created {
            return Err(state_error());
        }
        let result = self.drive(None);
        self.record(result)
    }
    pub fn advance(&mut self, bytes: &[u8]) -> Result<Step, Error> {
        if self.state != OperationState::AwaitingResponse {
            return Err(state_error());
        }
        let result = self.advance_inner(bytes);
        self.record(result)
    }
    fn advance_inner(&mut self, bytes: &[u8]) -> Result<Step, Error> {
        if bytes.len() > self.options.exchange.max_response_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        let response = ResponseApdu::parse(bytes)?;
        self.response_bytes = self
            .response_bytes
            .checked_add(response.data().len())
            .ok_or_else(|| Error::new(ErrorKind::LimitExceeded))?;
        if self.response_bytes > self.options.limits.max_total_response_bytes {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        let result = self
            .conversation
            .as_mut()
            .ok_or_else(state_error)?
            .advance(response, self.options)?;
        match result {
            None => self.exchange(),
            Some(response) => {
                self.conversation = None;
                self.drive(Some(response))
            }
        }
    }
    fn drive(&mut self, response: Option<ResponseData>) -> Result<Step, Error> {
        match self
            .machine
            .as_mut()
            .ok_or_else(state_error)?
            .next(response)?
        {
            Action::Done(value) => {
                self.output = Some(value);
                self.machine = None;
                self.conversation = None;
                self.state = OperationState::Completed;
                Ok(Step::Done)
            }
            Action::Command(command) => {
                self.conversation = Some(ConversationState::new(command, self.options)?);
                self.exchange()
            }
        }
    }
    fn exchange(&mut self) -> Result<Step, Error> {
        if self.exchanges >= self.options.limits.max_exchanges {
            return Err(Error::new(ErrorKind::LimitExceeded).at(Phase::Conversation));
        }
        self.exchanges += 1;
        self.state = OperationState::AwaitingResponse;
        Ok(Step::Exchange)
    }
    fn record(&mut self, result: Result<Step, Error>) -> Result<Step, Error> {
        if let Err(error) = &result {
            self.machine = None;
            self.conversation = None;
            self.error = Some(error.clone());
            self.state = OperationState::Failed;
        }
        result
    }
}
fn state_error() -> Error {
    Error::new(ErrorKind::OperationStateError)
}
struct SingleCommand {
    command: Option<LogicalCommand>,
}
impl Machine<ResponseData> for SingleCommand {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<ResponseData>, Error> {
        match response {
            Some(response) => Ok(Action::Done(response)),
            None => Ok(Action::Command(
                self.command.take().ok_or_else(state_error)?,
            )),
        }
    }
}
/// A low-level conversation returns the final status without applet-specific mapping.
pub fn conversation(
    command: LogicalCommand,
    options: OperationOptions,
) -> Result<Operation<ResponseData>, Error> {
    validate_command(&command, options)?;
    Operation::from_machine(
        SingleCommand {
            command: Some(command),
        },
        options,
    )
}

/// Preflight a fully known logical command before starting a multi-command operation.
pub fn validate_command(command: &LogicalCommand, options: OperationOptions) -> Result<(), Error> {
    ConversationState::new(command.clone(), options.validate()?).map(|_| ())
}
