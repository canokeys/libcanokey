use crate::*;
use canokey_protocol::{
    operation::{
        engine::{Action, Machine},
        LogicalCommand, ResponseData,
    },
    Phase,
};
use compatibility::{
    AlgorithmConfig, CompatibilityWarning, DeviceObservations, PivApplicationVersion, Support,
};
/// Read-only discovery scope. Both modes select Admin and change applet state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProbeMode {
    /// Read actual firmware, optional model and serial only; PIV remains unobserved.
    Minimal,
    /// Also select PIV, read its version and probe algorithm configuration when known safe.
    /// This is the default for constructing subsequent PIV operations.
    #[default]
    Piv,
}
/// Owned probe scope and channel/resource limits.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProbeOptions {
    /// Applet discovery scope; defaults to Piv.
    pub mode: ProbeMode,
    /// Limits copied into the constructed operation.
    pub operation: OperationOptions,
}
struct Probe {
    stage: usize,
    mode: ProbeMode,
    observations: DeviceObservations,
}
/// Construct a read-only probe yielding an immutable [`DeviceProfile`].
///
/// No connection or input reference is retained. The caller drives all APDUs
/// using [`Operation::start`] and [`Operation::advance`]. Probe changes applets,
/// so never insert it between another operation's authentication and target command.
/// It does not try credentials, write configuration, or establish a login.
///
/// # Errors
/// Construction rejects invalid operation options. During execution, required
/// command failures and malformed responses are errors. Recognized optional
/// unsupported/authentication-required statuses become profile warnings; other
/// failures propagate. Unknown firmware text is preserved rather than rejected.
///
/// See the [crate example](crate) for a complete offline drive loop.
pub fn probe_device(options: ProbeOptions) -> Result<Operation<DeviceProfile>, Error> {
    Operation::from_machine(
        Probe {
            stage: 0,
            mode: options.mode,
            observations: DeviceObservations::new(vec![]),
        },
        options.operation,
    )
}
impl Probe {
    fn optional(&mut self, response: &ResponseData, name: &'static str) -> Result<bool, Error> {
        if response.status.is_success() {
            return Ok(true);
        }
        let warning = match response.status.raw() {
            0x6d00 | 0x6e00 | 0x6a81 | 0x6a86 => {
                CompatibilityWarning::OptionalCommandUnsupported(name)
            }
            0x6982 => CompatibilityWarning::OptionalCommandNeedsAuthentication(name),
            _ => return Err(Error::status(response.status, Phase::Command, None)),
        };
        self.observations.warnings.push(warning);
        Ok(false)
    }
    fn finish(&self) -> Result<Action<DeviceProfile>, Error> {
        Ok(Action::Done(DeviceProfile::from_observations(
            self.observations.clone(),
        )?))
    }
}
impl Machine<DeviceProfile> for Probe {
    fn next(&mut self, response: Option<ResponseData>) -> Result<Action<DeviceProfile>, Error> {
        if let Some(response) = response {
            match self.stage {
                1 | 5 => response.ensure_success(Phase::Select)?,
                2 => {
                    response.ensure_success(Phase::Command)?;
                    if response.data.is_empty() || response.data.len() > 256 {
                        return Err(Error::new(ErrorKind::InvalidResponse));
                    }
                    self.observations.firmware_text = response.data.as_bytes().to_vec();
                }
                3 => {
                    if self.optional(&response, "model")? {
                        self.observations.model = Some(
                            std::str::from_utf8(response.data.as_bytes())
                                .map_err(|_| Error::new(ErrorKind::InvalidResponse))?
                                .to_owned(),
                        );
                    }
                }
                4 => {
                    if self.optional(&response, "serial")? {
                        if response.data.len() != 4 {
                            return Err(Error::new(ErrorKind::InvalidResponse));
                        }
                        self.observations.serial = Some(response.data.as_bytes().to_vec());
                    }
                }
                6 => {
                    response.ensure_success(Phase::Command)?;
                    let version: [u8; 3] = response
                        .data
                        .as_bytes()
                        .try_into()
                        .map_err(|_| Error::new(ErrorKind::InvalidResponse))?;
                    self.observations.piv_version = Some(PivApplicationVersion(version));
                }
                7 => {
                    if self.optional(&response, "algorithm_config")? {
                        self.observations.algorithm_config =
                            Some(AlgorithmConfig::parse(response.data.as_bytes())?);
                    }
                }
                _ => return Err(Error::new(ErrorKind::ProtocolViolation)),
            }
        }
        let mut command: LogicalCommand = match self.stage {
            0 => admin::command::select(),
            1 => admin::command::firmware(),
            2 => admin::command::model(),
            3 => admin::command::serial(),
            4 if self.mode == ProbeMode::Minimal => return self.finish(),
            4 => piv::command::select(),
            5 => piv::command::version(),
            6 => {
                let profile = DeviceProfile::from_observations(self.observations.clone())?;
                if profile.algorithm_config_read_support().support != Support::Supported {
                    return self.finish();
                }
                piv::command::algorithm_config()
            }
            7 => return self.finish(),
            _ => return Err(Error::new(ErrorKind::ProtocolViolation)),
        };
        // SELECT is used before actual firmware is known; explicit short Le is
        // compatible with every audited release and prevents legacy empty 61 loops.
        if command.le == canokey_protocol::ExpectedLength::Absent {
            command.le = canokey_protocol::ExpectedLength::Exact(256);
        }
        self.stage += 1;
        Ok(Action::Command(command))
    }
}
