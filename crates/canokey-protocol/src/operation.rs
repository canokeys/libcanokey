//! Owned operations and bounded logical-command conversations.
//!
//! Applications normally construct operations through applet factories. Use
//! [`conversation`](crate::operation::conversation) only when deliberately working at the raw command/status layer.
use crate::{
    ApduEncoding, ApduHeader, CommandApdu, Error, ErrorKind, ExpectedLength, Phase, ResponseApdu,
    SecretBytes, StatusWord,
};
use std::collections::VecDeque;

/// Caller-reported limits for a raw transport exchange.
/// Defaults to short APDUs: 261 command bytes and 258 response bytes.
#[derive(Clone, Copy, Debug)]
pub struct ExchangeOptions {
    /// Maximum complete command size, including header and Lc/Le.
    pub max_command_bytes: usize,
    /// Maximum complete response size, including SW1/SW2.
    pub max_response_bytes: usize,
    /// Permit extended encoding when the logical command also permits it.
    /// This does not discover or guarantee card support.
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
/// Budgets applied by the operation; not claims about card storage capacity.
#[derive(Clone, Copy, Debug)]
pub struct OperationLimits {
    /// Sum of response-data bytes across all exchanges, excluding SW (default 1 MiB).
    /// Applet parsers may reuse this as their decoded-output limit.
    pub max_total_response_bytes: usize,
    /// Maximum number of physical commands exposed, including retries/continuations
    /// (default 4096). Reading the same command again does not consume a count.
    pub max_exchanges: usize,
    /// Maximum data length of each logical command before segmentation
    /// (default 1 MiB); not an aggregate across a multi-command operation.
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
/// Owned channel constraints and resource budgets; default values are bounded.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperationOptions {
    /// Limits for complete physical APDUs.
    pub exchange: ExchangeOptions,
    /// Logical-command input, cumulative response, and exchange budgets.
    pub limits: OperationLimits,
}
impl OperationOptions {
    /// Validate budgets and return the unchanged options.
    ///
    /// # Errors
    /// Returns [`ErrorKind::InvalidArgument`] for command limits below five bytes,
    /// response limits below three bytes, or any zero operation budget.
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
/// The caller's next action after a successful start or advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Read `command()`, exchange it once, then call `advance()` with data plus SW.
    Exchange,
    /// Read or take the completed typed result; no command remains pending.
    Done,
}
/// Local lifecycle state, independent of card login or connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationState {
    /// Constructed but not started.
    Created,
    /// One physical command is available and awaits a complete response.
    AwaitingResponse,
    /// A typed result is available; working protocol state has been released.
    Completed,
    /// Protocol execution failed; the stored error is available.
    Failed,
    /// Active working state was discarded locally without performing I/O.
    Cancelled,
    /// The result has been moved out and cannot be read or taken again.
    ResultTaken,
}

/// Applet-specific conversation policy. OATH's non-ISO protocol is deliberately
/// not approximated by an ISO GET RESPONSE loop.
#[derive(Clone, Copy, Debug)]
pub enum Continuation {
    /// Follow 61xx with GET RESPONSE using the specified class byte.
    Iso7816 {
        /// Class byte for generated GET RESPONSE commands.
        cla: u8,
    },
    /// Return the final raw status without performing continuation.
    None,
}
/// Owned semantic command before physical encoding, splitting, or continuation.
/// Use applet builders when available so authentication and policy remain correct.
#[derive(Clone, Debug)]
pub struct LogicalCommand {
    /// Header used for the initial command and its chained fragments.
    pub header: ApduHeader,
    /// Owned command data, wiped when no longer needed.
    pub data: SecretBytes,
    /// Requested final response-data length.
    pub le: ExpectedLength,
    /// Permit short command chaining when one physical command is insufficient.
    pub allow_chaining: bool,
    /// Permit extended encoding when the exchange options also permit it.
    /// This does not discover or guarantee card support.
    pub allow_extended: bool,
    /// Allow one 6Cxx Le correction per physical command. Enable only when safe.
    pub correct_le: bool,
    /// Continuation policy; ISO GET RESPONSE with CLA 0 by default.
    pub continuation: Continuation,
}
impl LogicalCommand {
    /// Take ownership of command data with conservative encoding/retry defaults.
    /// Chaining, extended encoding and Le correction start disabled; ISO continuation
    /// uses CLA 0. Validation occurs when constructing a conversation.
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
/// Owned reassembled response with its final raw status.
/// A successful low-level conversation can still contain a non-9000 status.
#[derive(Debug)]
pub struct ResponseData {
    /// Reassembled response data without status words, wiped on drop.
    pub data: SecretBytes,
    /// Final status after any permitted continuation.
    pub status: StatusWord,
}
impl ResponseData {
    /// Require 9000, mapping any other status with the supplied phase and no
    /// secret reference. Authentication callers should use credential-aware mapping.
    ///
    /// # Errors
    /// Returns a status-derived [`Error`] retaining the raw status.
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
        fn progress(&self) -> Option<&T> {
            None
        }
        fn take_progress(&mut self) -> Option<T> {
            None
        }
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
///
/// Applet factories copy required profile configuration and own their inputs;
/// there is no caller lifetime, connection handle, or mutable global registry.
/// Hold one exclusive application connection lease across start and every advance.
/// Drop releases memory only, including on application transport failure.
///
/// # Examples
/// ```
/// use canokey_protocol::{ApduHeader, ExpectedLength, OperationState, Step};
/// use canokey_protocol::operation::{conversation, LogicalCommand};
/// let command = LogicalCommand::new(ApduHeader::new(0, 0xca, 0, 0),
///     vec![], ExpectedLength::Exact(256));
/// let mut op = conversation(command, Default::default())?;
/// assert_eq!(op.start()?, Step::Exchange);
/// assert_eq!(op.command()?.as_bytes(), &[0, 0xca, 0, 0, 0]);
/// // Offline response fixture; real applications supply their raw I/O result.
/// assert_eq!(op.advance(&[0x42, 0x90, 0])?, Step::Done);
/// let response = op.take_result()?;
/// assert_eq!(op.state(), OperationState::ResultTaken);
/// drop(op);
/// assert_eq!(response.data.as_bytes(), &[0x42]);
/// # Ok::<(), canokey_protocol::Error>(())
/// ```
pub struct Operation<T> {
    machine: Option<Box<dyn Machine<T>>>,
    conversation: Option<ConversationState>,
    output: Option<T>,
    progress: Option<T>,
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
            progress: None,
            error: None,
            state: OperationState::Created,
            options: options.validate()?,
            exchanges: 0,
            response_bytes: 0,
        })
    }
    /// Inspect the local lifecycle without advancing execution.
    pub fn state(&self) -> OperationState {
        self.state
    }
    /// Borrow the stored protocol failure, or `None` before any failure.
    /// Invalid-state getter/drive calls do not overwrite this error.
    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }
    /// Borrow partial results only for an operation explicitly designed to expose
    /// progress (currently PIV Batch). Ordinary operations return None. Failed
    /// batches retain completed items without retaining execution secrets.
    /// Returns None after cancellation/result transfer and on completion, when
    /// the ordinary result getter applies. Repeated calls never advance execution.
    pub fn progress(&self) -> Option<&T> {
        self.progress
            .as_ref()
            .or_else(|| self.machine.as_ref().and_then(|m| m.progress()))
    }
    /// Borrow the pending complete physical APDU. Repeated reads never resend it.
    ///
    /// # Errors
    /// Returns [`ErrorKind::OperationStateError`] outside AwaitingResponse.
    /// The borrow cannot outlive the next mutable call to this operation.
    pub fn command(&self) -> Result<&CommandApdu, Error> {
        if self.state != OperationState::AwaitingResponse {
            return Err(state_error());
        }
        self.conversation
            .as_ref()
            .map(|c| &c.current)
            .ok_or_else(state_error)
    }
    /// Borrow the completed typed result without card access.
    ///
    /// # Errors
    /// Returns [`ErrorKind::OperationStateError`] unless the state is Completed.
    pub fn result(&self) -> Result<&T, Error> {
        if self.state != OperationState::Completed {
            return Err(state_error());
        }
        self.output.as_ref().ok_or_else(state_error)
    }
    /// Move the result into caller ownership and enter ResultTaken.
    /// The result can outlive this operation.
    ///
    /// # Errors
    /// Returns [`ErrorKind::OperationStateError`] unless the state is Completed,
    /// including on any second attempt.
    pub fn take_result(&mut self) -> Result<T, Error> {
        if self.state != OperationState::Completed {
            return Err(state_error());
        }
        let value = self.output.take().ok_or_else(state_error)?;
        self.state = OperationState::ResultTaken;
        Ok(value)
    }
    /// Discard working data from Created/AwaitingResponse and enter Cancelled.
    /// Other states are unchanged. Does not cancel transport I/O, send logout, or
    /// roll back card effects; drain or isolate pending I/O before connection reuse.
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
    /// Start a Created operation, exposing its first command or completing locally.
    ///
    /// # Errors
    /// Returns [`ErrorKind::OperationStateError`] in any other state, without changing
    /// it. Construction/encoding/machine errors enter Failed and are retained.
    pub fn start(&mut self) -> Result<Step, Error> {
        if self.state != OperationState::Created {
            return Err(state_error());
        }
        let result = self.drive(None);
        self.record(result)
    }
    /// Consume one complete response (data followed by SW1/SW2) to the pending command.
    /// Input is borrowed only during this call. Do not supply transport errors or
    /// responses already processed by another continuation loop.
    ///
    /// # Errors
    /// Outside AwaitingResponse, returns [`ErrorKind::OperationStateError`] unchanged.
    /// Malformed responses, exhausted limits, conversation violations and applet
    /// failures enter Failed, retain the error and release working state.
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
            self.progress = self.machine.as_mut().and_then(|m| m.take_progress());
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
/// Construct a low-level operation that returns the final raw status.
///
/// Unlike applet factories, this does not SELECT, authenticate, or turn a final
/// non-9000 status into an applet error. It handles only the command's declared
/// chaining, continuation and Le-correction policy.
///
/// # Errors
/// Returns an error before execution for invalid options, input/encoding limits,
/// or a command that cannot fit the channel under its permitted encoding policy.
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

/// Preflight a fully known logical command without sending or retaining it.
///
/// # Errors
/// Returns invalid-option, input-limit, or physical-encoding errors that would
/// otherwise occur when constructing the command's conversation. This validates
/// host encoding constraints, not card support or authentication.
pub fn validate_command(command: &LogicalCommand, options: OperationOptions) -> Result<(), Error> {
    ConversationState::new(command.clone(), options.validate()?).map(|_| ())
}
