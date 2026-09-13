use crate::*;
use canokey_protocol::{
    operation::{
        engine::{Action, Machine},
        LogicalCommand, ResponseData,
    },
    Phase,
};
use compatibility::{
    AlgorithmConfig, Capability, CompatibilityWarning, DeviceObservations, PivApplicationVersion,
    Support,
};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProbeMode {
    Minimal,
    #[default]
    Piv,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct ProbeOptions {
    pub mode: ProbeMode,
    pub operation: OperationOptions,
}
struct Probe {
    stage: usize,
    mode: ProbeMode,
    observations: DeviceObservations,
}
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
        let command: LogicalCommand = match self.stage {
            0 => admin::command::select(),
            1 => admin::command::firmware(),
            2 => admin::command::model(),
            3 => admin::command::serial(),
            4 if self.mode == ProbeMode::Minimal => return self.finish(),
            4 => piv::command::select(),
            5 => piv::command::version(),
            6 => {
                let profile = DeviceProfile::from_observations(self.observations.clone())?;
                if profile.capability(Capability::AlgorithmExtensions).support != Support::Supported
                {
                    return self.finish();
                }
                piv::command::algorithm_config()
            }
            7 => return self.finish(),
            _ => return Err(Error::new(ErrorKind::ProtocolViolation)),
        };
        self.stage += 1;
        Ok(Action::Command(command))
    }
}
