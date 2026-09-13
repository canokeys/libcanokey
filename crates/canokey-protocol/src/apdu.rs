//! Physical ISO 7816 APDU encoding and borrowed response parsing.
//!
//! These codecs do not apply firmware rules, send commands, or interpret applet errors.
use crate::{Error, ErrorKind, Phase, SecretBytes};
/// Raw SW1/SW2 status, preserved even when the applet does not recognize it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusWord(u16);
impl StatusWord {
    /// Wrap the big-endian numeric status (for example, `0x9000`).
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }
    /// Return SW1 in the high byte and SW2 in the low byte.
    pub const fn raw(self) -> u16 {
        self.0
    }
    /// Return true only for `9000`; continuation and warning statuses are not success.
    pub const fn is_success(self) -> bool {
        self.0 == 0x9000
    }
}
/// Requested response-data length (Le), excluding SW1/SW2.
///
/// [`CommandApdu::encode`] validates the numeric range for the chosen encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedLength {
    /// Omit Le entirely; distinct from an encoded zero byte.
    Absent,
    /// Request 1..=256 bytes in short form or 1..=65536 in extended form.
    /// The maximum value encodes as zero; it does not require that many response bytes.
    Exact(u32),
}
/// Physical Lc/Le field widths; neither variant implies device support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApduEncoding {
    /// One-byte Lc/Le: at most 255 command-data bytes and Le up to 256.
    Short,
    /// Extended Lc/Le: at most 65535 command-data bytes and Le up to 65536.
    Extended,
}
/// Four-byte command header, without Lc, data, or Le.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApduHeader {
    /// Class byte, including any application-selected channel/chaining bits.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// First instruction parameter.
    pub p1: u8,
    /// Second instruction parameter.
    pub p2: u8,
}
impl ApduHeader {
    /// Construct a header without interpreting instruction semantics.
    pub const fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self { cla, ins, p1, p2 }
    }
}
/// Owned encoded command; Debug is redacted and its buffer is wiped on drop.
#[derive(Clone)]
pub struct CommandApdu {
    bytes: SecretBytes,
    header: ApduHeader,
    data_start: usize,
    data_len: usize,
    encoding: ApduEncoding,
}
impl std::fmt::Debug for CommandApdu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandApdu([REDACTED])")
    }
}
impl CommandApdu {
    /// Encode one complete physical APDU, copying `data` into a protected buffer.
    ///
    /// This does not split a logical command or check channel/device capabilities.
    /// Use [`crate::operation::conversation`] for chaining and continuation.
    ///
    /// # Errors
    /// Returns [`ErrorKind::InvalidArgument`] when data or Le exceeds the encoding
    /// range, or when `Exact(0)` is supplied.
    ///
    /// # Examples
    /// ```
    /// use canokey_protocol::{ApduEncoding, ApduHeader, CommandApdu, ExpectedLength};
    /// let command = CommandApdu::encode(
    ///     ApduHeader::new(0, 0xcb, 0x3f, 0xff),
    ///     &[0x5c, 1, 0x7e], ExpectedLength::Exact(256), ApduEncoding::Short,
    /// )?;
    /// assert_eq!(command.as_bytes(), &[0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 0]);
    /// # Ok::<(), canokey_protocol::Error>(())
    /// ```
    pub fn encode(
        header: ApduHeader,
        data: &[u8],
        le: ExpectedLength,
        encoding: ApduEncoding,
    ) -> Result<Self, Error> {
        let max = match encoding {
            ApduEncoding::Short => 256,
            ApduEncoding::Extended => 65536,
        };
        if data.len() >= max || matches!(le, ExpectedLength::Exact(n) if n == 0 || n > max as u32) {
            return Err(Error::new(ErrorKind::InvalidArgument));
        }
        let mut bytes = Vec::with_capacity(9 + data.len());
        bytes.extend_from_slice(&[header.cla, header.ins, header.p1, header.p2]);
        let extended = encoding == ApduEncoding::Extended;
        if !data.is_empty() {
            if extended {
                bytes.push(0);
                bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            } else {
                bytes.push(data.len() as u8);
            }
        } else if extended && le != ExpectedLength::Absent {
            bytes.push(0);
        }
        let data_start = bytes.len();
        bytes.extend_from_slice(data);
        if let ExpectedLength::Exact(n) = le {
            if extended {
                bytes.extend_from_slice(&(n as u16).to_be_bytes());
            } else {
                bytes.push(n as u8);
            }
        }
        Ok(Self {
            bytes: SecretBytes::new(bytes),
            header,
            data_start,
            data_len: data.len(),
            encoding,
        })
    }
    /// Borrow the complete encoded APDU. The caller sends these bytes unchanged.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
    pub(crate) fn corrected(&self, le: u32) -> Result<Self, Error> {
        Self::encode(
            self.header,
            &self.as_bytes()[self.data_start..self.data_start + self.data_len],
            ExpectedLength::Exact(le),
            self.encoding,
        )
    }
}
/// Borrowed response data and status. Parsing does not imply command success.
#[derive(Clone, Copy)]
pub struct ResponseApdu<'a> {
    data: &'a [u8],
    status: StatusWord,
}
impl<'a> ResponseApdu<'a> {
    /// Split a complete response into data and its final two status bytes.
    ///
    /// # Errors
    /// Returns [`ErrorKind::InvalidResponse`] during parsing for fewer than two bytes.
    /// No size limit is applied here; [`crate::Operation`] enforces exchange budgets.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 2 {
            return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing));
        }
        let n = bytes.len();
        Ok(Self {
            data: &bytes[..n - 2],
            status: StatusWord::new(u16::from_be_bytes([bytes[n - 2], bytes[n - 1]])),
        })
    }
    /// Borrow response data, excluding SW1/SW2, with the original input lifetime.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
    /// Return the raw final status without applet-specific interpretation.
    pub fn status(&self) -> StatusWord {
        self.status
    }
}
