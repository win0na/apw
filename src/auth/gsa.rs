//! GSA SRP login over the `GsService2` plist endpoint.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use base64::Engine;
use hmac::{Hmac, Mac};
use plist::{Dictionary, Value};
use sha2::Sha256;

use crate::auth::anisette::Identity;
use crate::auth::srp::PasswordScheme;
use crate::error::{Error, Result};

pub const DEFAULT_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2";

#[derive(Debug, Clone, Default)]
pub struct Status {
    pub ec: i64,
    pub em: String,
    pub au: Option<String>,
    pub hsc: Option<i64>,
    pub md_data: Option<Vec<u8>>,
}

impl Status {
    pub fn ok(&self) -> bool {
        self.ec == 0
    }

    pub fn message(&self) -> String {
        if self.em.is_empty() {
            format!("GSA returned status {}", self.ec)
        } else {
            format!("GSA returned {} ({})", self.em, self.ec)
        }
    }
}

pub struct InitResponse {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub server_public: Vec<u8>,
    pub continuation: String,
    pub scheme: PasswordScheme,
    pub status: Status,
}

pub struct CompleteResponse {
    pub m2: Vec<u8>,
    pub spd: Option<Vec<u8>>,
    pub status: Status,
    /// The PET from the `X-Apple-PE-Token` response header.
    pub pet: Option<String>,
}

pub struct SpdFields {
    pub adsid: String,
    pub dsid: String,
    pub gs_idms_token: String,
    pub pet: Option<String>,
}

pub struct Gsa {
    client: reqwest::Client,
    endpoint: String,
    identity: Identity,
}

impl Gsa {
    pub fn new(identity: Identity) -> Self {
        let endpoint = std::env::var("APW_GSA_ENDPOINT")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        Self {
            client: reqwest::Client::builder()
                .http1_only()
                .pool_max_idle_per_host(0)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            endpoint,
            identity,
        }
    }

    pub async fn init(&self, username: &str, public: &[u8]) -> Result<InitResponse> {
        let (response, _) = self
            .post(init_request(username, public, &self.identity))
            .await?;
        let dict = response_dict(&response)?;
        let status = status(dict);

        Ok(InitResponse {
            salt: required_data(dict, "s")?,
            iterations: required_integer(dict, "i")? as u32,
            server_public: required_data(dict, "B")?,
            continuation: required_string(dict, "c")?,
            scheme: PasswordScheme::parse(&required_string(dict, "sp")?)?,
            status,
        })
    }

    pub async fn complete(
        &self,
        username: &str,
        continuation: &str,
        m1: &[u8],
    ) -> Result<CompleteResponse> {
        let (response, pet) = self
            .post(complete_request(username, continuation, m1, &self.identity))
            .await?;
        let dict = response_dict(&response)?;
        let status = status(dict);

        Ok(CompleteResponse {
            m2: dict
                .get("M2")
                .and_then(Value::as_data)
                .unwrap_or_default()
                .to_vec(),
            spd: dict.get("spd").and_then(Value::as_data).map(<[u8]>::to_vec),
            status,
            pet,
        })
    }

    async fn post(&self, body: Value) -> Result<(Value, Option<String>)> {
        let mut bytes = Vec::new();
        plist::to_writer_xml(&mut bytes, &body)?;

        let response = self
            .client
            .post(&self.endpoint)
            .header("Content-Type", "text/x-xml-plist")
            .header("Accept", "*/*")
            .header("User-Agent", &self.identity.user_agent)
            .header("X-MMe-Client-Info", &self.identity.client_info)
            .header("Connection", "close")
            .body(bytes)
            .send()
            .await?;

        let status = response.status();
        if std::env::var_os("APW_DEBUG").is_some() {
            eprintln!(
                "gsa response headers: {:?}",
                response.headers().keys().collect::<Vec<_>>()
            );
        }
        let pet = pet_from_headers(response.headers());
        let body = response.bytes().await?;
        if !status.is_success() {
            return Err(Error::Message(format!("GSA answered HTTP {status}")));
        }
        Ok((plist::Value::from_reader_xml(&body[..])?, pet))
    }
}

fn init_request(username: &str, public: &[u8], identity: &Identity) -> Value {
    let mut request = Dictionary::new();
    request.insert("cpd".into(), cpd(identity));
    request.insert("A2k".into(), Value::Data(public.to_vec()));
    request.insert(
        "ps".into(),
        Value::Array(vec![
            Value::String("s2k".into()),
            Value::String("s2k_fo".into()),
        ]),
    );
    request.insert("u".into(), Value::String(username.into()));
    request.insert("o".into(), Value::String("init".into()));
    envelope(request)
}

fn complete_request(username: &str, continuation: &str, m1: &[u8], identity: &Identity) -> Value {
    let mut request = Dictionary::new();
    request.insert("c".into(), Value::String(continuation.into()));
    request.insert("M1".into(), Value::Data(m1.to_vec()));
    request.insert("u".into(), Value::String(username.into()));
    request.insert("o".into(), Value::String("complete".into()));
    request.insert("cpd".into(), cpd(identity));
    envelope(request)
}

fn envelope(request: Dictionary) -> Value {
    let mut header = Dictionary::new();
    header.insert("Version".into(), Value::String("1.0.1".into()));

    let mut root = Dictionary::new();
    root.insert("Header".into(), Value::Dictionary(header));
    root.insert("Request".into(), Value::Dictionary(request));
    Value::Dictionary(root)
}

fn cpd(identity: &Identity) -> Value {
    let mut cpd = Dictionary::new();
    for (name, value) in &identity.headers {
        cpd.insert(name.clone(), Value::String(value.clone()));
    }
    cpd.insert("bootstrap".into(), Value::Boolean(true));
    cpd.insert("icscrec".into(), Value::Boolean(true));
    cpd.insert("pbe".into(), Value::Boolean(false));
    cpd.insert("prkgen".into(), Value::Boolean(true));
    cpd.insert("svct".into(), Value::String("iCloud".into()));
    Value::Dictionary(cpd)
}

fn response_dict(value: &Value) -> Result<&Dictionary> {
    value
        .as_dictionary()
        .and_then(|root| root.get("Response"))
        .and_then(Value::as_dictionary)
        .ok_or_else(|| Error::Message("GSA response has no Response dictionary".into()))
}

fn status(dict: &Dictionary) -> Status {
    let Some(status) = dict.get("Status").and_then(Value::as_dictionary) else {
        return Status::default();
    };

    Status {
        ec: status
            .get("ec")
            .and_then(Value::as_signed_integer)
            .unwrap_or(0),
        em: status
            .get("em")
            .and_then(Value::as_string)
            .unwrap_or_default()
            .to_string(),
        au: status
            .get("au")
            .and_then(Value::as_string)
            .map(str::to_string),
        hsc: status.get("hsc").and_then(Value::as_signed_integer),
        md_data: status
            .get("X-Apple-I-MD-DATA")
            .and_then(Value::as_data)
            .map(<[u8]>::to_vec),
    }
}

fn required_data(dict: &Dictionary, key: &str) -> Result<Vec<u8>> {
    dict.get(key)
        .and_then(Value::as_data)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::Message(format!("GSA response has no {key}")))
}

fn required_integer(dict: &Dictionary, key: &str) -> Result<i64> {
    dict.get(key)
        .and_then(Value::as_signed_integer)
        .ok_or_else(|| Error::Message(format!("GSA response has no {key}")))
}

fn required_string(dict: &Dictionary, key: &str) -> Result<String> {
    dict.get(key)
        .and_then(Value::as_string)
        .map(str::to_string)
        .ok_or_else(|| Error::Message(format!("GSA response has no {key}")))
}

/// `spd` is AES-256-CBC under an HMAC-SHA256 expansion of the SRP key.
pub fn decrypt_spd(key: &[u8], spd: &[u8]) -> Result<Value> {
    let cipher_key = hmac_sha256(key, b"extra data key:")?;
    let iv = hmac_sha256(key, b"extra data iv:")?;

    let cipher = cbc::Decryptor::<aes::Aes256>::new_from_slices(&cipher_key, &iv[..16])
        .map_err(|_| Error::Message("cannot build the spd cipher".into()))?;

    let mut buffer = spd.to_vec();
    let plain = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| Error::Message("cannot decrypt spd".into()))?;

    Ok(plist::Value::from_reader_xml(plain)?)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Error::Message("invalid HMAC key".into()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub struct IdmsFields {
    pub adsid: String,
    pub gs_idms_token: String,
}

/// The fields needed to answer a two-factor challenge, before a PET exists.
pub fn idms_fields(value: &Value) -> Result<IdmsFields> {
    let dict = value
        .as_dictionary()
        .ok_or_else(|| Error::Message("spd is not a plist dictionary".into()))?;
    Ok(IdmsFields {
        adsid: required_string(dict, "adsid")?,
        gs_idms_token: required_string(dict, "GsIdmsToken")?,
    })
}

pub fn spd_fields(value: &Value) -> Result<SpdFields> {
    let dict = value
        .as_dictionary()
        .ok_or_else(|| Error::Message("spd is not a plist dictionary".into()))?;

    let pet = dict
        .get("t")
        .and_then(Value::as_dictionary)
        .and_then(|t| t.get("com.apple.gs.idms.pet"))
        .and_then(|pet| match pet {
            Value::String(token) => Some(token.as_str()),
            Value::Dictionary(pet) => pet.get("token").and_then(Value::as_string),
            _ => None,
        })
        .map(str::to_string);

    let adsid = required_string(dict, "adsid")?;
    let dsid = dict
        .get("DsPrsId")
        .and_then(Value::as_string)
        .unwrap_or(&adsid)
        .to_string();
    let gs_idms_token = dict
        .get("GsIdmsToken")
        .and_then(Value::as_string)
        .unwrap_or_default()
        .to_string();
    Ok(SpdFields {
        adsid,
        dsid,
        gs_idms_token,
        pet,
    })
}

pub fn pet_from_headers(headers: &reqwest::header::HeaderMap) -> Option<String> {
    for value in headers.get_all("x-apple-gs-token").iter() {
        let Ok(raw) = value.to_str() else { continue };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(raw) else {
            continue;
        };
        let Ok(text) = String::from_utf8(decoded) else {
            continue;
        };
        let parts: Vec<&str> = text.split(':').collect();
        if parts.first() == Some(&"com.apple.gs.idms.pet") {
            if std::env::var_os("APW_DEBUG").is_some() {
                eprintln!(
                    "gsa gs-token idms.pet: parts={} pet_len={}",
                    parts.len(),
                    parts.get(1).map(|part| part.len()).unwrap_or(0)
                );
            }
            return parts.get(1).map(|part| part.to_string());
        }
    }

    let raw = headers.get("x-apple-pe-token")?;
    let raw = raw.to_str().ok()?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(raw).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let parts: Vec<&str> = text.split(':').collect();
    if std::env::var_os("APW_DEBUG").is_some() {
        eprintln!(
            "gsa pe-token header: parts={} pet_len={}",
            parts.len(),
            parts.get(1).map(|part| part.len()).unwrap_or(0)
        );
    }
    parts.get(1).map(|part| part.to_string())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_and_scheme() {
        let mut status = Dictionary::new();
        status.insert("ec".into(), Value::from(0i64));
        status.insert("au".into(), Value::String("secondaryAuth".into()));
        status.insert("hsc".into(), Value::from(409i64));
        assert_eq!(status.get("ec").and_then(Value::as_signed_integer), Some(0));
        assert_eq!(
            PasswordScheme::parse("s2k_fo").unwrap(),
            PasswordScheme::S2kFo
        );
    }

    #[test]
    fn spd_round_trip() {
        let key = [7u8; 32];
        let cipher_key = hmac_sha256(&key, b"extra data key:").unwrap();
        let iv = hmac_sha256(&key, b"extra data iv:").unwrap();

        let mut dict = Dictionary::new();
        dict.insert("adsid".into(), Value::String("1234".into()));
        dict.insert("DsPrsId".into(), Value::String("5678".into()));
        dict.insert("GsIdmsToken".into(), Value::String("idms".into()));
        let mut pet = Dictionary::new();
        pet.insert("token".into(), Value::String("pet-token".into()));
        let mut t = Dictionary::new();
        t.insert("com.apple.gs.idms.pet".into(), Value::Dictionary(pet));
        dict.insert("t".into(), Value::Dictionary(t));

        let mut plain = Vec::new();
        plist::to_writer_xml(&mut plain, &Value::Dictionary(dict)).unwrap();

        let cipher =
            cbc::Encryptor::<aes::Aes256>::new_from_slices(&cipher_key, &iv[..16]).unwrap();
        use aes::cipher::BlockEncryptMut;
        let mut buffer = vec![0u8; plain.len() + 16];
        buffer[..plain.len()].copy_from_slice(&plain);
        let encrypted = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plain.len())
            .unwrap()
            .to_vec();

        let value = decrypt_spd(&key, &encrypted).unwrap();
        let fields = spd_fields(&value).unwrap();
        assert_eq!(fields.adsid, "1234");
        assert_eq!(fields.pet.as_deref(), Some("pet-token"));
    }
}
