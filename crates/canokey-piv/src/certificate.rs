//! PIV certificate containers (70 certificate, 71 information, FE LRC).
use canokey_protocol::{
    tlv::{TlvLimits, TlvReader},
    Error, ErrorKind, Phase, SecretBytes,
};
use std::io::Read;

/// Unwrapped certificate bytes. X.509 validation belongs to the caller.
#[derive(Debug)]
pub struct Certificate {
    der: SecretBytes,
    compressed: bool,
}
impl Certificate {
    /// Borrow the unwrapped/decompressed certificate payload.
    /// The accessor name describes its expected format; no X.509 validation occurred.
    pub fn der(&self) -> &[u8] {
        self.der.as_bytes()
    }
    /// Whether the original information field selected gzip compression.
    pub fn was_compressed(&self) -> bool {
        self.compressed
    }
    /// Parse the value of a PIV certificate object (without its outer 53 tag).
    /// Both encoded input and decompressed output are limited to `max_bytes`.
    /// Missing information means uncompressed; unknown information is rejected.
    /// Exactly one nonempty 70 field is required. A single one-byte 71 (00/01)
    /// and one empty FE field are optional. Other fields and duplicates fail.
    /// The returned value owns a copy; no input borrow is retained.
    ///
    /// # Errors
    /// Returns InvalidResponse for malformed containers, invalid/truncated gzip,
    /// failed CRC/size validation, empty output or trailing gzip members/data.
    /// Unsupported information bytes return UnsupportedProtocolVersion.
    /// Encoded input or decoded output exceeding `max_bytes` returns LimitExceeded.
    ///
    /// # Examples
    /// ```
    /// use canokey_piv::Certificate;
    /// // A framing fixture, not a valid X.509 certificate.
    /// let certificate = Certificate::from_object(
    ///     &[0x70, 2, 0x30, 0, 0x71, 1, 0, 0xfe, 0], 1024)?;
    /// assert_eq!(certificate.der(), &[0x30, 0]);
    /// assert!(!certificate.was_compressed());
    /// # Ok::<(), canokey_protocol::Error>(())
    /// ```
    pub fn from_object(data: &[u8], max_bytes: usize) -> Result<Self, Error> {
        let invalid = || Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing);
        let limit = || Error::new(ErrorKind::LimitExceeded).at(Phase::Parsing);
        if data.len() > max_bytes {
            return Err(limit());
        }
        let mut reader = TlvReader::new(
            data,
            TlvLimits {
                max_value_bytes: max_bytes,
                ..Default::default()
            },
        );
        let (mut certificate, mut info, mut lrc) = (None, None, false);
        while let Some(field) = reader.next()? {
            match field.tag.value() {
                0x70 if certificate.is_none() => certificate = Some(field.value),
                0x71 if info.is_none() && field.value.len() == 1 => info = Some(field.value[0]),
                0xfe if !lrc && field.value.is_empty() => lrc = true,
                _ => return Err(invalid()),
            }
        }
        let bytes = certificate.filter(|v| !v.is_empty()).ok_or_else(invalid)?;
        let compressed = match info.unwrap_or(0) {
            0 => false,
            1 => true,
            _ => return Err(Error::new(ErrorKind::UnsupportedProtocolVersion).at(Phase::Parsing)),
        };
        let der = if compressed {
            // bufread stops at the end of exactly one gzip member. Reject trailing
            // bytes/members, and read through EOF to verify the checksum and size.
            let mut decoder = flate2::bufread::GzDecoder::new(bytes);
            let mut output = SecretBytes::new(Vec::new());
            let mut chunk = [0u8; 4096];
            loop {
                let n = decoder.read(&mut chunk).map_err(|_| invalid())?;
                if n == 0 {
                    break;
                }
                if n > max_bytes.saturating_sub(output.len()) {
                    return Err(limit());
                }
                output.extend(&chunk[..n]);
            }
            if !decoder.into_inner().is_empty() || output.is_empty() {
                return Err(invalid());
            }
            output
        } else {
            SecretBytes::new(bytes.to_vec())
        };
        Ok(Self { der, compressed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn container(bytes: &[u8], info: u8) -> Vec<u8> {
        assert!(bytes.len() < 128);
        let mut out = vec![0x70, bytes.len() as u8];
        out.extend(bytes);
        out.extend([0x71, 1, info, 0xfe, 0]);
        out
    }
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }
    #[test]
    fn compressed_and_uncompressed() {
        for (bytes, info) in [(vec![0x30, 0], 0), (gzip(&[0x30, 0]), 1)] {
            let c = Certificate::from_object(&container(&bytes, info), 128).unwrap();
            assert_eq!(c.der(), &[0x30, 0]);
            assert_eq!(c.was_compressed(), info == 1);
        }
        assert!(Certificate::from_object(&[0x70, 1, 0x30], 3).is_ok());
    }
    #[test]
    fn rejects_malformed_containers_and_compression() {
        for bytes in [
            vec![],
            vec![0x70, 0],
            vec![0x70, 2, 0x30],
            vec![0x70, 1, 0x30, 0x70, 1, 0x30],
            vec![0x70, 1, 0x30, 0x71, 0],
            vec![0x70, 1, 0x30, 0xfe, 1, 0],
            container(&[1], 1),
        ] {
            assert!(Certificate::from_object(&bytes, 128).is_err());
        }
        assert_eq!(
            Certificate::from_object(&container(&[1], 2), 128)
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedProtocolVersion
        );
        let mut compressed = gzip(&[0x30, 0]);
        compressed.push(0);
        assert!(Certificate::from_object(&container(&compressed, 1), 128).is_err());
        compressed.pop();
        let n = compressed.len();
        compressed[n - 8] ^= 1; // Corrupt CRC.
        assert!(Certificate::from_object(&container(&compressed, 1), 128).is_err());
        compressed.truncate(n - 4);
        assert!(Certificate::from_object(&container(&compressed, 1), 128).is_err());
    }
    #[test]
    fn bounds_expansion_and_input() {
        let bytes = container(&gzip(&[0; 4096]), 1);
        assert_eq!(
            Certificate::from_object(&bytes, 128).unwrap_err().kind,
            ErrorKind::LimitExceeded
        );
        assert_eq!(
            Certificate::from_object(&[0x70, 1, 1], 2).unwrap_err().kind,
            ErrorKind::LimitExceeded
        );
    }
}
