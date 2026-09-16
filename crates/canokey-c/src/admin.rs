use super::*;
use canokey::admin;

/// Copied Admin request descriptor; fields unused by a request must be zero/NULL.
#[repr(C)]
pub struct CnkAdminRequest {
    /// Size of the complete supported descriptor.
    pub struct_size: u32,
    /// CNK_ADMIN_* request identifier, 1..24 (11 is reserved).
    pub kind: u32,
    /// Optional explicit current PIN; NULL/zero omits verification.
    pub pin: *const u8,
    /// Current PIN byte count.
    pub pin_len: usize,
    /// New PIN bytes for CHANGE_PIN, or nine raw bytes for WRITE_LEGACY_SM2.
    pub data: *const u8,
    /// Byte count of data; zero for other requests.
    pub data_len: usize,
    /// CONFIGURE: boolean presence bits 0 LED, 1 NDEF read-only, 2 NDEF, 3 WebUSB.
    /// CONFIGURE_SM2: presence bits 0 curve, 1 algorithm.
    /// SET_LEGACY_OPENPGP_TOUCH: index 0 SIG, 1 DEC, 2 AUT, 3 cache seconds.
    pub present: u32,
    /// CONFIGURE: values of selected boolean bits. SET_NFC: zero/one.
    /// RESET_APPLET: 1 OpenPGP, 2 PIV, 3 OATH, 4 NDEF, 5 CTAP, 6 PASS.
    /// Historical switches: zero/one. Legacy touch: boolean or cache seconds.
    pub values: u32,
    /// CONFIGURE: feature bits to modify, limited to 0x3f.
    pub feature_mask: u8,
    /// CONFIGURE: replacement bits, a subset of feature_mask.
    pub feature_values: u8,
    /// Reserved input bytes, must be zero.
    pub reserved: [u8; 2],
    /// CONFIGURE_SM2: replacement signed curve ID when selected.
    pub curve_id: i32,
    /// CONFIGURE_SM2: replacement signed algorithm ID when selected.
    pub algorithm_id: i32,
    /// Keyboard layout identifier for keymap writes.
    pub layout_id: u8,
    /// Keyboard keymap bytes (exactly 256 for WRITE_KBD_KEYMAP).
    pub keymap: *const u8,
    /// Keyboard keymap byte count.
    pub keymap_len: usize,
}
unsafe fn request(d: &CnkAdminRequest) -> Result<admin::Request, u32> {
    use admin::Request as R;
    if d.struct_size < std::mem::size_of::<CnkAdminRequest>() as u32
        || d.reserved != [0; 2]
        || (!matches!(d.kind, 12 | 24 | 30) && (!d.data.is_null() || d.data_len != 0))
        || (d.kind != 13 && (d.feature_mask != 0 || d.feature_values != 0))
        || (d.kind != 17 && (d.curve_id != 0 || d.algorithm_id != 0))
        || (!matches!(d.kind, 13 | 17 | 23) && d.present != 0)
        || (!matches!(d.kind, 13 | 15 | 18 | 20..=23) && d.values != 0)
    {
        return Err(ARG);
    }
    Ok(match d.kind {
        1 => R::Firmware,
        2 => R::Model,
        3 => R::Serial,
        4 => R::ChipId,
        5 => R::CoreCommit,
        6 => R::Configuration,
        7 => R::FlashUsage,
        8 => R::AppletUsage,
        9 => R::PinStatus,
        10 => R::VerifyPin,
        12 => R::ChangePin(admin::Pin::from_bytes(bytes(d.data, d.data_len)?).map_err(|_| ARG)?),
        13 => {
            if d.present & !15 != 0 || d.values & !d.present != 0 {
                return Err(ARG);
            }
            let flag = |bit| (d.present & bit != 0).then_some(d.values & bit != 0);
            R::Configure(admin::ConfigurationPatch {
                led_on: flag(1),
                ndef_read_only: flag(2),
                ndef_enabled: flag(4),
                webusb_landing: flag(8),
                feature_mask: d.feature_mask,
                feature_values: d.feature_values,
            })
        }
        14 => R::NfcStatus,
        15 if d.values <= 1 => R::SetNfc(d.values != 0),
        16 => R::Sm2Configuration,
        17 => {
            if d.present & !3 != 0
                || d.present & 1 == 0 && d.curve_id != 0
                || d.present & 2 == 0 && d.algorithm_id != 0
            {
                return Err(ARG);
            }
            R::ConfigureSm2(admin::Sm2Patch {
                curve_id: (d.present & 1 != 0).then_some(d.curve_id),
                algorithm_id: (d.present & 2 != 0).then_some(d.algorithm_id),
            })
        }
        18 => R::ResetApplet(match d.values {
            1 => admin::Applet::OpenPgp,
            2 => admin::Applet::Piv,
            3 => admin::Applet::Oath,
            4 => admin::Applet::Ndef,
            5 => admin::Applet::Ctap,
            6 => admin::Applet::Pass,
            _ => return Err(ARG),
        }),
        19 => R::FactoryReset,
        20 if d.values <= 1 => R::SetKeyboardInterface(d.values != 0),
        21 if d.values <= 1 => R::SetKeyboardReturn(d.values != 0),
        22 if d.values <= 1 => R::SetLegacyPivExtensions(d.values != 0),
        23 => R::SetLegacyOpenPgpTouch(match (d.present, d.values) {
            (0, 0..=1) => admin::LegacyOpenPgpTouch::Signature(d.values != 0),
            (1, 0..=1) => admin::LegacyOpenPgpTouch::Decryption(d.values != 0),
            (2, 0..=1) => admin::LegacyOpenPgpTouch::Authentication(d.values != 0),
            (3, 0..=255) => admin::LegacyOpenPgpTouch::CacheSeconds(d.values as u8),
            _ => return Err(ARG),
        }),
        24 => R::WriteLegacySm2(
            admin::LegacySm2Configuration::from_bytes(bytes(d.data, d.data_len)?)
                .map_err(|_| ARG)?,
        ),
        25 => R::KeyboardLayout,
        26 => R::KeyboardKeymap,
        27 => R::SetKeyboardKeymap {
            layout_id: d.layout_id,
            keymap: admin::KeyboardKeymap::from_bytes(bytes(d.keymap, d.keymap_len)?)
                .map_err(|_| ARG)?,
        },
        28 => R::ClearKeyboardKeymap,
        29 => R::PassConfiguration,
        30 => R::SetPassConfiguration(bytes(d.data, d.data_len)?.to_vec()),
        _ => return Err(ARG),
    })
}
/// Construct an owned Admin request. Copies PINs, fields and options before return.
///
/// # Safety
/// Follow the crate pointer contract. profile/request must be live non-NULL;
/// input spans readable, out writable/non-NULL, optional options/error versioned.
#[no_mangle]
pub unsafe extern "C" fn cnk_admin_new(
    profile: *const CnkProfile,
    descriptor: *const CnkAdminRequest,
    opts: *const CnkOptions,
    out: *mut *mut CnkOperation,
    error: *mut CnkError,
) -> u32 {
    create(out, error, || {
        let d = descriptor.as_ref().ok_or(ARG)?;
        let request = request(d)?;
        let pin = if d.pin.is_null() && d.pin_len == 0 {
            None
        } else {
            Some(admin::Pin::from_bytes(bytes(d.pin, d.pin_len)?).map_err(|e| failure(e, error))?)
        };
        admin::operation(
            &profile.as_ref().ok_or(ARG)?.0,
            request,
            pin,
            options(opts)?,
        )
        .map(Inner::Admin)
        .map_err(|e| failure(e, error))
    })
}
/// Caller-owned Admin result/progress POD. Unused fields are zero.
#[repr(C)]
pub struct CnkAdminOutcome {
    /// Initialized supported structure size.
    pub struct_size: u32,
    /// 0 none, 1 bytes, 2 configuration, 3 flash, 4 applet usage, 5 PIN, 6 NFC,
    /// 7 SM2, 8 legacy configuration, 9 legacy SM2 (flags bit 0: enabled).
    pub value_kind: u32,
    /// Number of writes confirmed by empty 9000 responses.
    pub confirmed_writes: usize,
    /// Zero/one profile invalidation; meaningful in partial results too.
    pub reprobe_required: u32,
    /// PIN: bit 0 verified, bit 1 blocked, bit 2 remaining present. NFC: zero/one.
    pub flags: u32,
    /// PIN retries if present; otherwise zero.
    pub retries_remaining: u32,
    /// Flash used KiB; otherwise zero.
    pub used_kib: u32,
    /// Flash total KiB; otherwise zero.
    pub total_kib: u32,
    /// SM2 signed curve ID; otherwise zero.
    pub curve_id: i32,
    /// SM2 signed algorithm ID; otherwise zero.
    pub algorithm_id: i32,
}
/// Copy Admin result or current/failed progress; never execute an APDU.
/// Byte/configuration/usage values are also available from result_copy_bytes on completion.
///
/// # Safety
/// Follow the crate pointer contract. op must be live without mutation/free;
/// out must be writable/non-NULL with initialized struct_size.
#[no_mangle]
pub unsafe extern "C" fn cnk_operation_admin_outcome(
    op: *const CnkOperation,
    out: *mut CnkAdminOutcome,
) -> u32 {
    guard(|| {
        if out.is_null() || (*out).struct_size < std::mem::size_of::<CnkAdminOutcome>() as u32 {
            return ARG;
        }
        let Some(op) = op.as_ref() else {
            return ARG;
        };
        if op.poisoned {
            return STATE;
        }
        let Inner::Admin(p) = &op.inner else {
            return TYPE;
        };
        let Some(v) = p.result().ok().or_else(|| p.progress()) else {
            return STATE;
        };
        let mut value = CnkAdminOutcome {
            struct_size: (*out).struct_size,
            value_kind: 0,
            confirmed_writes: v.confirmed_writes,
            reprobe_required: u32::from(v.reprobe_required),
            flags: 0,
            retries_remaining: 0,
            used_kib: 0,
            total_kib: 0,
            curve_id: 0,
            algorithm_id: 0,
        };
        use admin::Value;
        value.value_kind = match &v.value {
            Value::None => 0,
            Value::Bytes(_) => 1,
            Value::Configuration(_) => 2,
            Value::LegacyConfiguration(_) => 8,
            Value::LegacySm2Configuration(c) => {
                value.flags = u32::from(c.enabled());
                9
            }
            Value::FlashUsage(f) => {
                value.used_kib = f.used_kib.into();
                value.total_kib = f.total_kib.into();
                3
            }
            Value::AppletUsage(_) => 4,
            Value::KeyboardLayout(_) | Value::KeyboardKeymap(_) => 1,
            Value::PinStatus(s) => {
                value.flags = u32::from(s.verified)
                    | (u32::from(s.blocked) << 1)
                    | (u32::from(s.retries_remaining.is_some()) << 2);
                value.retries_remaining = s.retries_remaining.unwrap_or(0).into();
                5
            }
            Value::NfcStatus(on) => {
                value.flags = u32::from(*on);
                6
            }
            Value::Sm2Configuration(s) => {
                value.curve_id = s.curve_id;
                value.algorithm_id = s.algorithm_id;
                7
            }
            Value::PassSlots(_) => 10,
        };
        ptr::write(out, value);
        OK
    })
}
pub(super) fn result_bytes(value: &admin::Value) -> Option<Vec<u8>> {
    Some(match value {
        admin::Value::Bytes(b) => b.clone(),
        admin::Value::Configuration(c) => c.raw().to_vec(),
        admin::Value::LegacyConfiguration(c) => c.raw().to_vec(),
        admin::Value::LegacySm2Configuration(c) => c.raw().to_vec(),
        admin::Value::AppletUsage(entries) => entries
            .iter()
            .flat_map(|e| {
                let b = e.logical_bytes.to_be_bytes();
                [e.applet_id, e.flags, b[0], b[1], b[2], b[3]]
            })
            .collect(),
        admin::Value::Sm2Configuration(s) => s.to_bytes().to_vec(),
        admin::Value::KeyboardLayout(id) => vec![*id],
        admin::Value::KeyboardKeymap(map) => map.as_bytes().to_vec(),
        admin::Value::PassSlots(slots) => {
            let encode = |slot: &admin::PassSlotState| -> Vec<u8> {
                match slot {
                    admin::PassSlotState::Off => vec![0x00],
                    admin::PassSlotState::Static { append_enter } => {
                        vec![0x02, u8::from(*append_enter)]
                    }
                    admin::PassSlotState::HmacSha1 => vec![0x03],
                    admin::PassSlotState::Oath { name, append_enter } => {
                        let mut v = Vec::with_capacity(name.len() + 3);
                        v.push(0x01);
                        v.push(name.len() as u8);
                        v.extend_from_slice(name);
                        v.push(u8::from(*append_enter));
                        v
                    }
                    admin::PassSlotState::Unknown(t) => vec![*t],
                }
            };
            let mut v = encode(&slots.short);
            v.extend(encode(&slots.long));
            v
        }
        _ => return None,
    })
}
