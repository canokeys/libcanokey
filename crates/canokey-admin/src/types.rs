use canokey_compat::{AdminConfigurationLayout, DeviceProfile};
use canokey_protocol::{Error, ErrorKind, SecretBytes};

/// Fixed 128-entry keyboard HID map (modifier/usage pairs).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyboardKeymap([u8; 256]);
impl std::fmt::Debug for KeyboardKeymap { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_tuple("KeyboardKeymap").field(&"<redacted>").finish() } }
impl KeyboardKeymap {
    /// Copy exactly 256 mapping bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> { Ok(Self(bytes.try_into().map_err(|_| Error::new(ErrorKind::InvalidArgument))?)) }
    /// Return the complete modifier/usage table.
    pub fn as_bytes(&self) -> &[u8; 256] { &self.0 }
}

/// Owned unpadded Admin PIN, six through 64 bytes. Debug redacts its contents.
#[derive(Debug)]
pub struct Pin(pub(crate) SecretBytes);
impl Pin {
    /// Copy bytes after validating their length. No character restrictions apply.
    /// Returns `InvalidPin` outside the applet's six through 64 byte range.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if !(6..=64).contains(&bytes.len()) {
            return Err(Error::new(ErrorKind::InvalidPin));
        }
        Ok(Self(SecretBytes::new(bytes.to_vec())))
    }
}

/// Six-byte device configuration; reserved and unknown bits are retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configuration([u8; 6]);
impl Configuration {
    /// Parse the current layout, rejecting wrong lengths and nonboolean flags.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let raw: [u8; 6] = data.try_into().map_err(|_| invalid())?;
        if [0, 2, 3, 4].iter().any(|&i| raw[i] > 1) {
            return Err(invalid());
        }
        Ok(Self(raw))
    }
    /// Complete observed bytes, including the reserved byte and unknown feature bits.
    pub fn raw(&self) -> &[u8; 6] {
        &self.0
    }
    /// Whether the LED is normally on.
    pub fn led_on(&self) -> bool {
        self.0[0] != 0
    }
    /// Whether NDEF writes are disabled.
    pub fn ndef_read_only(&self) -> bool {
        self.0[2] != 0
    }
    /// Whether NDEF is enabled.
    pub fn ndef_enabled(&self) -> bool {
        self.0[3] != 0
    }
    /// Whether the WebUSB landing page is enabled.
    pub fn webusb_landing(&self) -> bool {
        self.0[4] != 0
    }
    /// Feature bits: PASS, OpenPGP CCID/NFC, PIV CCID/NFC, WebAuthn (bits 0..5).
    pub fn features(&self) -> u8 {
        self.0[5]
    }
}
/// Historical configuration retaining its original layout and bytes. Optional
/// getters distinguish absent flags from false and never reinterpret reserved bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyConfiguration {
    raw: Vec<u8>,
    layout: AdminConfigurationLayout,
}
impl LegacyConfiguration {
    /// Parse an audited pre-3.1 response using profile evidence, not length guessing.
    /// Rejects a current layout, wrong length, or nonboolean defined flags.
    pub fn parse(profile: &DeviceProfile, bytes: &[u8]) -> Result<Self, Error> {
        use AdminConfigurationLayout::*;
        let layout = profile.admin_configuration_layout()?;
        let (n, flags): (usize, &[usize]) = match layout {
            TouchPolicies => (7, &[0, 1, 2]),
            Basic => (5, &[0, 1, 2, 3, 4]),
            KeyboardReturn => (6, &[0, 1, 2, 3, 4, 5]),
            Reserved => (6, &[0, 2, 3, 4]),
            Features => return Err(Error::new(ErrorKind::InvalidArgument)),
        };
        if bytes.len() != n || flags.iter().any(|&i| bytes[i] > 1) {
            return Err(invalid());
        }
        Ok(Self {
            raw: bytes.to_vec(),
            layout,
        })
    }
    /// Exact observed bytes, including reserved values and raw touch policy octets.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Firmware-selected interpretation of the bytes.
    pub fn layout(&self) -> AdminConfigurationLayout {
        self.layout
    }
    /// Whether the LED is normally on.
    pub fn led_on(&self) -> bool {
        self.raw[0] != 0
    }
    /// Whether NDEF writes are disabled.
    pub fn ndef_read_only(&self) -> bool {
        self.raw[2] != 0
    }
    /// NDEF availability flag, absent on 1.3.
    pub fn ndef_enabled(&self) -> Option<bool> {
        (self.layout != AdminConfigurationLayout::TouchPolicies).then(|| self.raw[3] != 0)
    }
    /// WebUSB landing-page flag, absent on 1.3.
    pub fn webusb_landing(&self) -> Option<bool> {
        (self.layout != AdminConfigurationLayout::TouchPolicies).then(|| self.raw[4] != 0)
    }
    /// Keyboard-interface flag, absent from 3.0 onward.
    pub fn keyboard_interface(&self) -> Option<bool> {
        (self.layout != AdminConfigurationLayout::Reserved).then(|| self.raw[1] != 0)
    }
    /// Append-return flag, reported only by the 1.6.2–2.x layout.
    pub fn keyboard_return(&self) -> Option<bool> {
        (self.layout == AdminConfigurationLayout::KeyboardReturn).then(|| self.raw[5] != 0)
    }
    /// Raw 1.3 SIG/DEC/AUT touch flags and cache seconds; absent in later layouts.
    pub fn openpgp_touch(&self) -> Option<[u8; 4]> {
        (self.layout == AdminConfigurationLayout::TouchPolicies)
            .then(|| [self.raw[3], self.raw[4], self.raw[5], self.raw[6]])
    }
}
/// Nine-byte 3.0.x SM2 configuration: enable byte plus two native-layout i32s.
/// Firmware copies its packed struct verbatim. The integer byte order is not a
/// portable protocol; callers explicitly encode/decode the eight identifier bytes.
/// This type never applies the 3.1 big-endian format to a historical device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacySm2Configuration([u8; 9]);
impl LegacySm2Configuration {
    /// Copy exactly nine bytes and validate the leading boolean enable flag.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let raw: [u8; 9] = bytes.try_into().map_err(|_| invalid())?;
        if raw[0] > 1 {
            return Err(invalid());
        }
        Ok(Self(raw))
    }
    /// Exact native-layout bytes suitable for an explicit legacy write.
    pub fn raw(&self) -> &[u8; 9] {
        &self.0
    }
    /// Observed enable flag; not available in the modern configuration.
    pub fn enabled(&self) -> bool {
        self.0[0] != 0
    }
}
/// Admin 1.3 OpenPGP touch setting; later firmware uses OpenPGP UIF instead.
#[derive(Clone, Copy, Debug)]
pub enum LegacyOpenPgpTouch {
    /// Require touch for signatures (Admin 09/00).
    Signature(bool),
    /// Require touch for decryption (Admin 09/01).
    Decryption(bool),
    /// Require touch for authentication (Admin 09/02).
    Authentication(bool),
    /// Cache touch for this many seconds (Admin 09/03).
    CacheSeconds(u8),
}
/// Partial updates; unspecified fields and unselected feature bits are preserved.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfigurationPatch {
    /// Replace the LED flag when present.
    pub led_on: Option<bool>,
    /// Replace the NDEF read-only flag when present.
    pub ndef_read_only: Option<bool>,
    /// Replace NDEF availability when present.
    pub ndef_enabled: Option<bool>,
    /// Replace the WebUSB landing-page flag when present.
    pub webusb_landing: Option<bool>,
    /// Bits to modify, limited to 0x3f. A zero mask leaves all features unchanged.
    pub feature_mask: u8,
    /// Values of selected bits; bits outside feature_mask must be zero.
    pub feature_values: u8,
}
/// Observed physical flash usage, in KiB; no used/total relationship is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlashUsage {
    /// Used physical storage reported by firmware.
    pub used_kib: u8,
    /// Total physical storage reported by firmware.
    pub total_kib: u8,
}
/// One logical storage record; unknown applet IDs and flags remain observable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppletUsage {
    /// 0 system, 1 Admin, 2 OpenPGP, 3 PIV, 4 OATH, 5 CTAP, 6 NDEF, 7 PASS.
    pub applet_id: u8,
    /// Bit 0 reports missing paths/attributes; remaining bits are uninterpreted.
    pub flags: u8,
    /// Logical payload bytes (not physical flash allocation).
    pub logical_bytes: u32,
}
/// CTAP SM2 identifiers; wire encoding is two signed big-endian i32 values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sm2Configuration {
    /// Configured COSE curve identifier.
    pub curve_id: i32,
    /// Configured COSE algorithm identifier.
    pub algorithm_id: i32,
}
impl Sm2Configuration {
    /// Parse eight bytes without applying identifier assignment policy.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 8 {
            return Err(invalid());
        }
        Ok(Self {
            curve_id: i32::from_be_bytes(bytes[..4].try_into().map_err(|_| invalid())?),
            algorithm_id: i32::from_be_bytes(bytes[4..].try_into().map_err(|_| invalid())?),
        })
    }
    /// Encode both signed identifiers without an enable flag.
    pub fn to_bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&self.curve_id.to_be_bytes());
        bytes[4..].copy_from_slice(&self.algorithm_id.to_be_bytes());
        bytes
    }
}
/// Partial SM2 update. The operation reads and preserves the other identifier.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sm2Patch {
    /// Replacement curve identifier, subject to firmware's reserved-ID rules.
    pub curve_id: Option<i32>,
    /// Replacement algorithm identifier, subject to firmware's reserved-ID rules.
    pub algorithm_id: Option<i32>,
}
/// Applet whose data and credentials an authenticated Admin reset destroys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applet {
    /// OpenPGP keys, objects and passwords.
    OpenPgp,
    /// PIV keys, objects, PIN/PUK and management key.
    Piv,
    /// OATH credentials and access key.
    Oath,
    /// NDEF content and configuration.
    Ndef,
    /// CTAP credentials and configuration.
    Ctap,
    /// Password applet data.
    Pass,
}
/// Owned Admin request. Mutations require a supplied PIN, except factory reset.
#[derive(Debug)]
pub enum Request {
    /// Read original firmware text bytes.
    Firmware,
    /// Read vendor model bytes.
    Model,
    /// Read four serial bytes.
    Serial,
    /// Read vendor-specific chip identifier bytes, possibly empty.
    ChipId,
    /// Read embedded core commit text bytes.
    CoreCommit,
    /// Read the six-byte device configuration.
    Configuration,
    /// Read physical flash usage in KiB.
    FlashUsage,
    /// Read eight logical applet usage records.
    AppletUsage,
    /// Read the configured keyboard layout identifier.
    KeyboardLayout,
    /// Read the 256-byte keyboard HID map.
    KeyboardKeymap,
    /// Replace the keyboard HID map for a layout.
    SetKeyboardKeymap {
        /// Host-defined layout identifier.
        layout_id: u8,
        /// Complete 256-byte HID mapping.
        keymap: KeyboardKeymap,
    },
    /// Clear the stored keyboard HID map.
    ClearKeyboardKeymap,
    /// Read raw PASS applet configuration.
    PassConfiguration,
    /// Replace raw PASS applet configuration bytes.
    SetPassConfiguration(Vec<u8>),
    /// Query Admin verification/retries without submitting a PIN.
    PinStatus,
    /// Verify the separately supplied PIN without another target command.
    VerifyPin,
    /// Verify the supplied old PIN, then replace it with this owned PIN.
    ChangePin(Pin),
    /// Read current configuration then write only changed selected fields.
    Configure(ConfigurationPatch),
    /// Set the historical keyboard interface flag (40/03); requires pre-3.0.
    SetKeyboardInterface(bool),
    /// Set the historical append-return flag (40/06); requires 1.6.2–2.x.
    SetKeyboardReturn(bool),
    /// Enable/disable 2.x PIV algorithm extensions (40/07). Reprobe afterward;
    /// READ CONFIG does not report this flag and no previous value is inferred.
    SetLegacyPivExtensions(bool),
    /// Set OpenPGP touch through Admin 09 on 1.3 only. Never sends CTAP reset.
    SetLegacyOpenPgpTouch(LegacyOpenPgpTouch),
    /// Write all nine explicit native-layout SM2 bytes on 3.0.x only.
    WriteLegacySm2(LegacySm2Configuration),
    /// Read vendor NFC availability; vendor support is determined by the response.
    NfcStatus,
    /// Change vendor NFC availability; the connection may disappear after sending.
    SetNfc(bool),
    /// Read the authenticated CTAP SM2 configuration.
    Sm2Configuration,
    /// Read and patch CTAP SM2 identifiers.
    ConfigureSm2(Sm2Patch),
    /// Explicitly destroy one applet's contents using Admin authorization.
    ResetApplet(Applet),
    /// Explicit whole-device reset. Requires an already blocked Admin PIN and
    /// card-enforced physical presence; never submits PIN guesses or retries.
    FactoryReset,
}
/// Empty-VERIFY observations; total retry capacity is not reported by this command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinStatus {
    /// Whether Admin verification is currently active.
    pub verified: bool,
    /// Remaining retries, absent when verified or when only blocked is reported.
    pub retries_remaining: Option<u8>,
    /// Whether authentication is blocked.
    pub blocked: bool,
}
/// Owned result data. Read bytes are preserved without interpreting text encoding.
#[derive(Debug)]
pub enum Value {
    /// No response payload, including the initial partial-write progress value.
    None,
    /// Firmware, model, serial, chip ID or core commit bytes.
    Bytes(Vec<u8>),
    /// Device configuration read result (not a speculative post-write snapshot).
    Configuration(Configuration),
    /// Pre-3.1 configuration with optional fields and original raw bytes.
    LegacyConfiguration(LegacyConfiguration),
    /// 3.0.x SM2 enable flag and uninterpreted native-layout identifier bytes.
    LegacySm2Configuration(LegacySm2Configuration),
    /// Physical usage read result.
    FlashUsage(FlashUsage),
    /// Logical usage records.
    AppletUsage(Vec<AppletUsage>),
    /// Keyboard layout identifier.
    KeyboardLayout(u8),
    /// Complete keyboard HID mapping.
    KeyboardKeymap(KeyboardKeymap),
    /// Empty-VERIFY observations.
    PinStatus(PinStatus),
    /// Vendor NFC flag.
    NfcStatus(bool),
    /// SM2 identifier read result.
    Sm2Configuration(Sm2Configuration),
}
/// Result and retained progress for an Admin operation. No rollback is implied.
#[derive(Debug)]
pub struct Outcome {
    /// Final read result, or None for mutations and partial progress.
    pub value: Value,
    /// Number of mutation commands acknowledged with an empty 9000 response.
    pub confirmed_writes: usize,
    /// A profile-affecting write has been exposed; reprobe even if its response
    /// fails or is lost. Caller credential/object caches may also need invalidation.
    pub reprobe_required: bool,
}
pub(crate) fn invalid() -> Error {
    Error::new(ErrorKind::InvalidResponse).at(canokey_protocol::Phase::Parsing)
}
