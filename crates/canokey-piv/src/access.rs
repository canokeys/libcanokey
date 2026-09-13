//! SELECT and explicit authentication around a dependent machine.
use crate::*;
use management::ManagementMachine;

enum Stage {
    Begin,
    Select,
    Management,
    Pin,
    Target,
}
struct Selected<T> {
    stage: Stage,
    management: Option<ManagementMachine>,
    pin: Option<Pin>,
    target: Box<dyn Machine<T>>,
}
impl<T> Selected<T> {
    fn target_or_pin(&mut self) -> Result<Action<T>, Error> {
        if let Some(pin) = self.pin.take() {
            self.stage = Stage::Pin;
            Ok(Action::Command(command::verify_pin(&pin)))
        } else {
            self.stage = Stage::Target;
            self.target.next(None)
        }
    }
    fn management(&mut self, response: Option<ResponseData>) -> Result<Action<T>, Error> {
        let machine = self
            .management
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
        match machine.next(response)? {
            Action::Command(command) => Ok(Action::Command(command)),
            Action::Done(()) => {
                self.management = None; // Drop key and challenge before target execution.
                self.target_or_pin()
            }
        }
    }
}
impl<T> Machine<T> for Selected<T> {
    fn progress(&self) -> Option<&T> {
        if matches!(self.stage, Stage::Target) {
            self.target.progress()
        } else {
            None
        }
    }
    fn take_progress(&mut self) -> Option<T> {
        if matches!(self.stage, Stage::Target) {
            self.target.take_progress()
        } else {
            None
        }
    }
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<T>, Error> {
        match self.stage {
            Stage::Begin => {
                self.stage = Stage::Select;
                Ok(Action::Command(command::select()))
            }
            Stage::Select => {
                response
                    .ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?
                    .ensure_success(Phase::Select)?;
                if self.management.is_some() {
                    self.stage = Stage::Management;
                    self.management(None)
                } else {
                    self.target_or_pin()
                }
            }
            Stage::Management => self.management(response),
            Stage::Pin => {
                let response = response.ok_or_else(|| Error::new(ErrorKind::ProtocolViolation))?;
                require_auth(&response, SecretReference::Pin)?;
                if !response.data.is_empty() {
                    return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Authentication));
                }
                self.stage = Stage::Target;
                self.target.next(None)
            }
            Stage::Target => self.target.next(response),
        }
    }
}

pub(crate) fn with_access<T: 'static>(
    profile: &DeviceProfile,
    access: Access,
    target: impl Machine<T> + 'static,
    options: OperationOptions,
) -> Result<Operation<T>, Error> {
    require(profile)?;
    options.validate()?;
    canokey_protocol::operation::validate_command(&command::select(), options)?;
    let (management, pin) = match access {
        Access::None => (None, None),
        Access::Pin(pin) => (None, Some(pin)),
        Access::Management(auth) => (Some(auth), None),
        Access::PinAndManagement { pin, management } => (Some(management), Some(pin)),
    };
    if let Some(auth) = &management {
        auth.validate(profile, options)?;
    }
    if let Some(pin) = &pin {
        canokey_protocol::operation::validate_command(&command::verify_pin(pin), options)?;
    }
    Operation::from_machine(
        Selected {
            stage: Stage::Begin,
            management: management.map(ManagementMachine::new),
            pin,
            target: Box::new(target),
        },
        options,
    )
}

pub(crate) fn prepare<T: 'static>(
    command: LogicalCommand,
    options: OperationOptions,
    parse: impl FnOnce(ResponseData) -> Result<T, Error> + Send + 'static,
) -> Result<Sequence<T>, Error> {
    canokey_protocol::operation::validate_command(&command, options)?;
    Ok(Sequence {
        pending: vec![request(command, Phase::Command, None)].into(),
        current: None,
        parse: Some(Box::new(parse)),
    })
}
