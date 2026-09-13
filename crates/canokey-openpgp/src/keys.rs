use crate::{types::invalid, *};
use canokey_key::{curve_len, rsa_len};
use canokey_protocol::{
    tlv::{Tag, TlvLimits, TlvReader, TlvWriter},
    Error, ErrorKind, SecretBytes,
};
pub(crate) const ALGORITHMS: [Algorithm; 9] = [
    Algorithm::Rsa2048,
    Algorithm::Rsa3072,
    Algorithm::Rsa4096,
    Algorithm::EccP256,
    Algorithm::EccP384,
    Algorithm::EccP521,
    Algorithm::Secp256k1,
    Algorithm::Ed25519,
    Algorithm::X25519,
];
pub(crate) fn attributes(slot: Slot, a: Algorithm) -> Result<Vec<u8>, Error> {
    if !ALGORITHMS.contains(&a)
        || slot == Slot::Decryption && a == Algorithm::Ed25519
        || slot != Slot::Decryption && a == Algorithm::X25519
    {
        return Err(Error::new(ErrorKind::UnsupportedAlgorithm));
    }
    if let Some(n) = rsa_len(a) {
        return Ok(vec![1, ((n * 8) >> 8) as u8, 0, 0, 32, 2]);
    }
    let mut v = vec![if slot == Slot::Decryption {
        0x12
    } else if a == Algorithm::Ed25519 {
        0x16
    } else {
        0x13
    }];
    v.extend_from_slice(match a {
        Algorithm::EccP256 => &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7],
        Algorithm::EccP384 => &[0x2b, 0x81, 4, 0, 0x22],
        Algorithm::EccP521 => &[0x2b, 0x81, 4, 0, 0x23],
        Algorithm::Secp256k1 => &[0x2b, 0x81, 4, 0, 10],
        Algorithm::Ed25519 => &[0x2b, 6, 1, 4, 1, 0xda, 0x47, 15, 1],
        Algorithm::X25519 => &[0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1],
        _ => return Err(invalid()),
    });
    Ok(v)
}
pub(crate) fn one(bytes: &[u8], tag: u32) -> Result<&[u8], Error> {
    let mut r = TlvReader::new_ber(bytes, TlvLimits::default());
    let f = r.next()?.ok_or_else(invalid)?;
    if f.tag.value() != tag || r.next()?.is_some() {
        return Err(invalid());
    }
    Ok(f.value)
}
pub(crate) fn observed(
    bytes: &[u8],
    slot: Slot,
    profile: &canokey_compat::DeviceProfile,
) -> Result<Algorithm, Error> {
    let app = ApplicationData::parse_with_profile(profile, bytes, bytes.len())?;
    let attr = app.algorithm_attributes(slot)?.ok_or_else(invalid)?;
    for a in ALGORITHMS {
        if let Ok(expected) = attributes(slot, a) {
            if attr == expected
                || rsa_len(a).is_some() && attr.len() == 6 && attr[..3] == expected[..3]
            {
                return Ok(a);
            }
        }
    }
    Err(Error::new(ErrorKind::UnsupportedAlgorithm))
}
pub(crate) fn wrap(tag: &[u8], value: &[u8]) -> Result<SecretBytes, Error> {
    let mut w = TlvWriter::new(4096);
    w.push(Tag::from_bytes(tag)?, value)?;
    Ok(w.into_bytes())
}
fn length(v: &mut SecretBytes, n: usize) {
    if n < 128 {
        v.extend(&[n as u8]);
    } else if n <= 255 {
        v.extend(&[0x81, n as u8]);
    } else {
        v.extend(&[0x82, (n >> 8) as u8, n as u8]);
    }
}
pub(crate) fn import(slot: Slot, a: Algorithm, key: &PrivateKey) -> Result<SecretBytes, Error> {
    attributes(slot, a)?;
    let mut template = SecretBytes::default();
    let mut data = SecretBytes::default();
    let mut component = |tag: u8, bytes: &[u8]| {
        template.extend(&[tag]);
        length(&mut template, bytes.len());
        data.extend(bytes);
    };
    match key {
        PrivateKey::Rsa {
            exponent,
            p,
            q,
            q_inverse,
            d_p,
            d_q,
        } => {
            let n = rsa_len(a).ok_or_else(|| Error::new(ErrorKind::InvalidArgument))? / 2;
            if [p, q, q_inverse, d_p, d_q].iter().any(|v| v.len() != n) || exponent == &[0; 4] {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }
            component(0x91, exponent);
            for (tag, b) in [
                (0x92, p),
                (0x93, q),
                (0x94, q_inverse),
                (0x95, d_p),
                (0x96, d_q),
            ] {
                component(tag, b.as_bytes());
            }
        }
        PrivateKey::Ec(bytes) => {
            let n = curve_len(a)
                .or_else(|| {
                    [Algorithm::Ed25519, Algorithm::X25519]
                        .contains(&a)
                        .then_some(32)
                })
                .ok_or_else(|| Error::new(ErrorKind::InvalidArgument))?;
            if bytes.len() != n {
                return Err(Error::new(ErrorKind::InvalidArgument));
            }
            component(0x92, bytes.as_bytes());
        }
    }
    let mut body = SecretBytes::new(vec![slot.wire(), 0]);
    body.extend(wrap(&[0x7f, 0x48], template.as_bytes())?.as_bytes());
    body.extend(wrap(&[0x5f, 0x48], data.as_bytes())?.as_bytes());
    let bytes = wrap(&[0x4d], body.as_bytes())?;
    if bytes.len() > 2048 {
        return Err(Error::new(ErrorKind::LimitExceeded));
    }
    Ok(bytes)
}
pub(crate) fn sign_input(a: Algorithm, bytes: &[u8]) -> Result<(), Error> {
    attributes(Slot::Signature, a)?;
    let max = rsa_len(a)
        .map(|n| n * 2 / 5)
        .or_else(|| curve_len(a))
        .unwrap_or(255);
    if bytes.len() > max {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    Ok(())
}
pub(crate) fn signature_len(a: Algorithm) -> usize {
    rsa_len(a).unwrap_or_else(|| curve_len(a).map_or(64, |n| 2 * n))
}
pub(crate) fn derive_input(a: Algorithm, bytes: &[u8]) -> Result<SecretBytes, Error> {
    attributes(Slot::Decryption, a)?;
    let valid = if let Some(n) = curve_len(a) {
        bytes.len() == 1 + 2 * n && bytes.first() == Some(&4)
    } else {
        a == Algorithm::X25519 && bytes.len() == 32
    };
    if !valid {
        return Err(Error::new(ErrorKind::InvalidArgument));
    }
    wrap(
        &[0xa6],
        wrap(&[0x7f, 0x49], wrap(&[0x86], bytes)?.as_bytes())?.as_bytes(),
    )
}
