use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};
use crate::model::{Algorithm, Totp};

const MAX_DIGITS: u32 = 9;

pub fn generate(totp: &Totp, at: SystemTime) -> Result<String> {
    let key = decode_secret(&totp.secret)?;
    let digits = totp.digits.clamp(1, MAX_DIGITS);
    let period = totp.period.max(1);
    let counter = at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / period;
    let code = hotp(&key, counter, totp.algorithm)?;
    let modulus = 10u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        code % modulus,
        width = digits as usize
    ))
}

pub fn seconds_remaining(totp: &Totp, at: SystemTime) -> u64 {
    let period = totp.period.max(1);
    let elapsed = at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    period - (elapsed % period)
}

pub fn hotp(key: &[u8], counter: u64, algorithm: Algorithm) -> Result<u32> {
    let message = counter.to_be_bytes();
    let digest = match algorithm {
        Algorithm::Sha1 => hmac_sha1(key, &message)?,
        Algorithm::Sha256 => hmac_sha256(key, &message)?,
        Algorithm::Sha512 => hmac_sha512(key, &message)?,
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let slice = digest
        .get(offset..offset + 4)
        .ok_or_else(|| Error::Invalid("truncated HMAC digest".into()))?;
    let value = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
    Ok(value & 0x7fff_ffff)
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key)
        .map_err(|_| Error::Invalid("invalid HMAC key length".into()))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Error::Invalid("invalid HMAC key length".into()))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key)
        .map_err(|_| Error::Invalid("invalid HMAC key length".into()))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalized.is_empty() {
        return Err(Error::Invalid("TOTP secret is empty".into()));
    }
    let padding = (8 - normalized.len() % 8) % 8;
    let mut padded = normalized;
    padded.extend(std::iter::repeat_n('=', padding));
    BASE32
        .decode(padded.as_bytes())
        .map_err(|_| Error::Invalid("TOTP secret is not valid base32".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Totp;

    fn totp(secret: &str, algorithm: Algorithm) -> Totp {
        Totp {
            secret: secret.into(),
            algorithm,
            digits: 8,
            period: 30,
            issuer: None,
            account_name: None,
        }
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(seconds)
    }

    // RFC 6238 appendix B. The SHA-1 secret is "12345678901234567890",
    // the SHA-256 secret is 32 bytes and the SHA-512 secret is 64 bytes.
    #[test]
    fn rfc6238_sha1() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = generate(&totp(secret, Algorithm::Sha1), at(59)).unwrap();
        assert_eq!(code, "94287082");
    }

    #[test]
    fn rfc6238_sha256() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
        let code = generate(&totp(secret, Algorithm::Sha256), at(59)).unwrap();
        assert_eq!(code, "46119246");
    }

    #[test]
    fn rfc6238_sha512() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=";
        let code = generate(&totp(secret, Algorithm::Sha512), at(59)).unwrap();
        assert_eq!(code, "90693936");
    }

    #[test]
    fn six_digits_and_remaining() {
        let mut t = totp("GEZDGNBVGY3TQOJQ", Algorithm::Sha1);
        t.digits = 6;
        let code = generate(&t, at(59)).unwrap();
        assert_eq!(code.len(), 6);
        assert_eq!(seconds_remaining(&t, at(59)), 1);
        assert_eq!(seconds_remaining(&t, at(60)), 30);
    }

    #[test]
    fn rejects_bad_secret() {
        assert!(generate(&totp("not base32!", Algorithm::Sha1), at(59)).is_err());
    }
}
