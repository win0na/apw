use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};
use crate::model::{Algorithm, Totp};

const MAX_DIGITS: u32 = 9;

/// A one-time-code configuration parsed from an `otpauth://` URI or a bare
/// base32 secret, ready to be written into a metadata record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSpec {
    /// Raw base32-decoded secret bytes, the form Apple stores.
    pub secret: Vec<u8>,
    pub digits: u32,
    pub period: u32,
    /// 0 is SHA-1, 1 SHA-256, 2 SHA-512, matching the vault's metadata.
    pub algorithm: u8,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
    /// The URI this spec came from, if any.
    pub original_url: Option<String>,
}

impl TotpSpec {
    /// The vault view of this spec, with the secret re-encoded as base32.
    pub fn to_totp(&self) -> Totp {
        Totp {
            secret: data_encoding::BASE32_NOPAD.encode(&self.secret),
            algorithm: match self.algorithm {
                1 => Algorithm::Sha256,
                2 => Algorithm::Sha512,
                _ => Algorithm::Sha1,
            },
            digits: self.digits,
            period: u64::from(self.period),
            issuer: self.issuer.clone(),
            account_name: self.account_name.clone(),
        }
    }
}

/// Parse an `otpauth://totp/...` URI or a bare base32 secret.
///
/// A bare secret uses the usual defaults: SHA-1, six digits, a 30-second
/// period. Query keys are case-insensitive and values are percent-decoded.
pub fn parse_spec(input: &str) -> Result<TotpSpec> {
    let input = input.trim();
    if input.is_empty() {
        return Err(Error::Invalid(
            "a TOTP secret or otpauth URI is required".into(),
        ));
    }
    if input
        .get(..10)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("otpauth://"))
    {
        return parse_uri(input);
    }
    Ok(TotpSpec {
        secret: decode_secret(input)?,
        digits: 6,
        period: 30,
        algorithm: 0,
        issuer: None,
        account_name: None,
        original_url: None,
    })
}

fn parse_uri(input: &str) -> Result<TotpSpec> {
    let rest = &input["otpauth://".len()..];
    let (target, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (kind, label) = target.split_once('/').unwrap_or((target, ""));
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(Error::Invalid(format!(
            "unsupported otpauth type {kind:?}; only totp is supported"
        )));
    }

    let mut secret = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    let mut issuer = None;
    let mut account_name = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value);
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(value),
            "algorithm" => {
                algorithm = Some(match value.to_ascii_uppercase().as_str() {
                    "SHA1" => 0,
                    "SHA256" => 1,
                    "SHA512" => 2,
                    other => {
                        return Err(Error::Invalid(format!(
                            "unsupported TOTP algorithm {other}; use SHA1, SHA256, or SHA512"
                        )))
                    }
                })
            }
            "digits" => {
                let parsed = value.parse::<u32>().map_err(|_| {
                    Error::Invalid(format!("TOTP digits must be a number, got {value:?}"))
                })?;
                if !matches!(parsed, 6..=8) {
                    return Err(Error::Invalid(format!(
                        "TOTP digits must be 6, 7, or 8, got {parsed}"
                    )));
                }
                digits = Some(parsed);
            }
            "period" => {
                let parsed = value.parse::<u32>().map_err(|_| {
                    Error::Invalid(format!("TOTP period must be a number, got {value:?}"))
                })?;
                if parsed == 0 {
                    return Err(Error::Invalid("TOTP period must be greater than 0".into()));
                }
                period = Some(parsed);
            }
            "issuer" => issuer = Some(value),
            "accountname" | "account" => account_name = Some(value),
            _ => {}
        }
    }

    let secret = secret.ok_or_else(|| Error::Invalid("the otpauth URI has no secret".into()))?;

    let label = percent_decode(label);
    let (label_issuer, label_account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer.trim().to_string()), account.trim()),
        None => (None, label.trim()),
    };
    if account_name.is_none() && !label_account.is_empty() {
        account_name = Some(label_account.to_string());
    }
    if issuer.is_none() {
        issuer = label_issuer.filter(|value| !value.is_empty());
    }

    Ok(TotpSpec {
        secret: decode_secret(&secret)?,
        digits: digits.unwrap_or(6),
        period: period.unwrap_or(30),
        algorithm: algorithm.unwrap_or(0),
        issuer,
        account_name,
        original_url: Some(input.to_string()),
    })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
                match hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

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
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
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

    #[test]
    fn parses_an_otpauth_uri_with_parameters() {
        let spec = parse_spec(
            "otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60",
        )
        .expect("parses");
        assert_eq!(spec.secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(spec.digits, 8);
        assert_eq!(spec.period, 60);
        assert_eq!(spec.algorithm, 1);
        assert_eq!(spec.issuer.as_deref(), Some("Example"));
        assert_eq!(spec.account_name.as_deref(), Some("alice@example.com"));
        assert!(spec.original_url.is_some());

        let totp = spec.to_totp();
        assert_eq!(totp.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.algorithm, Algorithm::Sha256);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.period, 60);
    }

    #[test]
    fn parses_a_bare_base32_secret() {
        for input in [
            "JBSWY3DPEHPK3PXP",
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "JBSW-Y3DP-EHPK-3PXP",
            "JBSWY3DPEHPK3PXP====",
        ] {
            let spec = parse_spec(input).expect("parses");
            assert_eq!(spec.secret, b"Hello!\xde\xad\xbe\xef");
            assert_eq!(spec.digits, 6);
            assert_eq!(spec.period, 30);
            assert_eq!(spec.algorithm, 0);
            assert!(spec.issuer.is_none());
            assert!(spec.original_url.is_none());
        }
    }

    #[test]
    fn rejects_invalid_and_empty_secrets() {
        assert!(parse_spec("").is_err());
        assert!(parse_spec("   ").is_err());
        // 1 is not in the base32 alphabet.
        assert!(parse_spec("JBSW1Y3DPEHPK3PXP").is_err());
        // A URI without a secret is incomplete.
        assert!(parse_spec("otpauth://totp/Example?issuer=Example").is_err());
        // Digits and periods outside the supported values are refused.
        assert!(parse_spec("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=5").is_err());
        assert!(parse_spec("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&period=0").is_err());
        assert!(
            parse_spec("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&algorithm=MD5").is_err()
        );
    }
}
