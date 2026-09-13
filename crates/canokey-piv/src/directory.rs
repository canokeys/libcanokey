//! The directory uses a fixed one-byte payload length, not BER long-form length.
use crate::*;
use canokey_protocol::{ApduHeader, ExpectedLength};

/// Non-fatal inconsistency in one fixed-width directory entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryIssue {
    /// Slot reference is outside the ordinary asymmetric slot set.
    UnknownSlot,
    /// An earlier entry used the same slot reference; both are retained.
    DuplicateSlot,
    /// Neither key nor certificate nor an extension flag is present.
    EmptyFlags,
    /// Flag bits other than key/certificate are present.
    UnknownFlags,
    /// An entry without a key nevertheless asserts key metadata bytes.
    KeyFieldsWithoutKey,
}
/// One owned six-byte observation. Unknown values and source order are preserved.
#[derive(Debug)]
pub struct DirectoryEntry {
    /// Raw slot reference.
    pub reference: u8,
    /// Raw flags; bit 0 means key, bit 1 means certificate.
    pub flags: u8,
    /// Raw algorithm, origin, PIN policy and touch policy, in wire order.
    /// Meaningful as key fields only when has_key is true.
    pub key_fields: [u8; 4],
    /// Algorithm resolved from the profile when a key is present and ID is known.
    pub algorithm: Option<Algorithm>,
    /// Entry inconsistencies, without dropping the entry or inventing defaults.
    pub issues: Vec<DirectoryIssue>,
}
impl DirectoryEntry {
    /// Whether the entry asserts a key is present.
    pub fn has_key(&self) -> bool {
        self.flags & 1 != 0
    }
    /// Whether the entry asserts a certificate is present, independent of a key.
    pub fn has_certificate(&self) -> bool {
        self.flags & 2 != 0
    }
}
/// Owned directory response. Unknown versions preserve bytes without decoding entries.
#[derive(Debug)]
pub struct MetadataDirectory {
    raw: SecretBytes,
    version: u8,
    entries: Option<Vec<DirectoryEntry>>,
}
impl MetadataDirectory {
    /// Copy and parse a bounded directory response; no card access occurs.
    /// The five-byte header contains a single-byte payload length even above 127.
    /// Version 1 requires at most 24 six-byte entries; malformed framing fails.
    /// Unknown versions retain their payload, with entries returning None.
    pub fn parse(profile: &DeviceProfile, data: &[u8], limit: usize) -> Result<Self, Error> {
        if data.len() > limit {
            return Err(Error::new(ErrorKind::LimitExceeded));
        }
        let invalid = || Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing);
        if data.len() < 5
            || data[0..2] != [1, 1]
            || data[3] != 2
            || data.len() != 5 + data[4] as usize
        {
            return Err(invalid());
        }
        let version = data[2];
        let entries = if version == 1 {
            if data[4] as usize % 6 != 0 || data[4] > 144 {
                return Err(invalid());
            }
            let mut seen = [false; 256];
            let mut entries = Vec::new();
            for item in data[5..].chunks_exact(6) {
                let reference = item[0];
                let flags = item[1];
                let mut issues = Vec::new();
                if !matches!(reference, 0x9a | 0x9c | 0x9d | 0x9e | 0x82..=0x95) {
                    issues.push(DirectoryIssue::UnknownSlot);
                }
                if seen[reference as usize] {
                    issues.push(DirectoryIssue::DuplicateSlot);
                }
                seen[reference as usize] = true;
                if flags == 0 {
                    issues.push(DirectoryIssue::EmptyFlags);
                }
                if flags & !3 != 0 {
                    issues.push(DirectoryIssue::UnknownFlags);
                }
                if flags & 1 == 0 && item[2..].iter().any(|b| *b != 0) {
                    issues.push(DirectoryIssue::KeyFieldsWithoutKey);
                }
                entries.push(DirectoryEntry {
                    reference,
                    flags,
                    key_fields: [item[2], item[3], item[4], item[5]],
                    algorithm: if flags & 1 != 0 {
                        profile.algorithm_from_wire_id(item[2])
                    } else {
                        None
                    },
                    issues,
                });
            }
            Some(entries)
        } else {
            None
        };
        Ok(Self {
            raw: SecretBytes::new(data.to_vec()),
            version,
            entries,
        })
    }
    /// Complete original fixed-header response bytes.
    pub fn raw(&self) -> &[u8] {
        self.raw.as_bytes()
    }
    /// Asserted protocol version.
    pub fn version(&self) -> u8 {
        self.version
    }
    /// Source-order entries for understood version 1, otherwise None.
    pub fn entries(&self) -> Option<&[DirectoryEntry]> {
        self.entries.as_deref()
    }
}
/// Read the key/certificate directory under one SELECT and optional authentication.
/// Requires evidenced directory support. Bounds/framing failures and card status
/// errors propagate; per-entry inconsistencies remain inspectable diagnostics.
pub fn read_metadata_directory(
    profile: &DeviceProfile,
    access: Access,
    options: OperationOptions,
) -> Result<Operation<MetadataDirectory>, Error> {
    let target = prepare_directory(profile, options)?;
    access::with_access(profile, access, target, options)
}
pub(crate) fn prepare_directory(
    profile: &DeviceProfile,
    options: OperationOptions,
) -> Result<Sequence<MetadataDirectory>, Error> {
    profile
        .capability(Capability::MetadataDirectory)
        .require()?;
    let snapshot = profile.clone();
    let mut command = LogicalCommand::new(
        ApduHeader::new(0, 0xf7, 1, 0),
        vec![],
        ExpectedLength::Exact(256),
    );
    command.correct_le = true;
    access::prepare(command, options, move |r| {
        r.ensure_success(Phase::Command)?;
        MetadataDirectory::parse(
            &snapshot,
            r.data.as_bytes(),
            options.limits.max_total_response_bytes,
        )
    })
}
