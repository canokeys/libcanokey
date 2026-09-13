use crate::{Error, ErrorKind, Phase, SecretBytes};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusWord(u16);
impl StatusWord {
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u16 {
        self.0
    }
    pub const fn is_success(self) -> bool {
        self.0 == 0x9000
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedLength {
    Absent,
    Exact(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApduEncoding {
    Short,
    Extended,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApduHeader {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
}
impl ApduHeader {
    pub const fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self { cla, ins, p1, p2 }
    }
}
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
#[derive(Clone, Copy)]
pub struct ResponseApdu<'a> {
    data: &'a [u8],
    status: StatusWord,
}
impl<'a> ResponseApdu<'a> {
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
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
    pub fn status(&self) -> StatusWord {
        self.status
    }
}
