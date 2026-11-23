//! Escrow recovery and bottle decryption.
//!
//! Escrow SRP uses the RFC 5054 2048-bit group with trimmed public values, a
//! DSID username, and the device passcode as the password. The recovered
//! bottle decrypts with HKDF-SHA384 under the account's `adsid`.

use std::time::Duration;

use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::Zero;
use plist::{Dictionary, Value};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha384};

use crate::auth::anisette::{self, Identity};
use crate::auth::srp;
use crate::error::{Error, Result};
use crate::octagon::keys::PeerKeys;
use crate::wire::Reader;

const ESCROW_USER_AGENT: &str = "com.apple.sbd/638.100.48 com.apple.iCloudHelper/282";
const USER_ACTION: &str = "com.apple.sbd: escrow recovery";

const HKDF_SYMMETRIC: &[u8] = b"Escrow Symmetric Key";

pub struct Escrow {
    http: reqwest::Client,
    base: String,
    email: String,
    dsid: String,
    adsid: String,
    pet: String,
    mme_token: String,
    cloudkit_token: String,
    identity: Identity,
}

pub struct Init {
    pub dsid: String,
    pub club_type: Option<u64>,
    pub identifier: Vec<u8>,
    pub salt: Vec<u8>,
    pub server_public: Vec<u8>,
    pub header: Vec<u8>,
}

pub struct Recovery {
    pub m2: Vec<u8>,
    pub header: Vec<u8>,
    pub sections: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Bottle {
    pub label: String,
    pub peer_id: String,
    pub bottle_id: String,
    pub ct: Vec<u8>,
    pub tag: Vec<u8>,
    pub iv: Vec<u8>,
}

pub struct Recovered {
    pub peer_id: String,
    pub keys: PeerKeys,
}

impl Escrow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base: &str,
        email: &str,
        dsid: &str,
        adsid: &str,
        pet: &str,
        mme_token: &str,
        cloudkit_token: &str,
        identity: &Identity,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .http1_only()
                .pool_max_idle_per_host(0)
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            base: base.trim_end_matches('/').to_string(),
            email: email.to_string(),
            dsid: dsid.to_string(),
            adsid: adsid.to_string(),
            pet: pet.to_string(),
            mme_token: mme_token.to_string(),
            cloudkit_token: cloudkit_token.to_string(),
            identity: identity.clone(),
        }
    }

    /// GETRECORDS: list the account's escrow records. Spends no attempt.
    pub async fn list_records(&self) -> Result<Vec<(String, Value)>> {
        let mut request = Dictionary::new();
        request.insert("command".into(), Value::String("GETRECORDS".into()));
        request.insert(
            "label".into(),
            Value::String("com.apple.securebackup.record".into()),
        );
        request.insert("transactionUUID".into(), Value::String(uuid()));
        request.insert("userActionLabel".into(), Value::String(USER_ACTION.into()));
        request.insert("version".into(), Value::Integer(1.into()));

        let response = self.invoke("get_records", request).await?;
        let list = response
            .get("metadataList")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut out = Vec::new();
        for entry in list {
            let Some(dict) = entry.as_dictionary() else {
                continue;
            };
            let label = dict
                .get("label")
                .and_then(Value::as_string)
                .unwrap_or_default()
                .to_string();
            let metadata = dict
                .get("metadata")
                .and_then(Value::as_string)
                .map(base64_decode)
                .transpose()?
                .and_then(|bytes| plist::from_bytes(&bytes).ok())
                .unwrap_or(Value::Dictionary(Dictionary::new()));
            out.push((label, metadata));
        }
        Ok(out)
    }

    /// SRP_INIT: send A, receive the salt, B, and the DSID.
    pub async fn srp_init(&self, label: &str, public: &[u8]) -> Result<Init> {
        let mut request = Dictionary::new();
        request.insert("command".into(), Value::String("SRP_INIT".into()));
        request.insert("label".into(), Value::String(label.into()));
        request.insert("transactionUUID".into(), Value::String(uuid()));
        request.insert("userActionLabel".into(), Value::String(USER_ACTION.into()));
        request.insert("version".into(), Value::Integer(1.into()));
        request.insert(
            "blob".into(),
            Value::String(base64::engine::general_purpose::STANDARD.encode(public)),
        );

        let response = self.invoke("srp_init", request).await?;
        let dsid = response
            .get("dsid")
            .and_then(Value::as_string)
            .ok_or_else(|| Error::Message("escrow did not return a DSID".into()))?
            .to_string();
        let club_type = response
            .get("clubTypeID")
            .and_then(Value::as_unsigned_integer);
        let blob = response
            .get("respBlob")
            .and_then(Value::as_string)
            .ok_or_else(|| Error::Message("escrow did not return a response blob".into()))?;
        let blob = base64_decode(blob)?;
        let (header, sections) = unpack(&blob, 24, 3)?;
        if sections.len() != 3 {
            return Err(Error::Message(
                "escrow SRP_INIT returned the wrong shape".into(),
            ));
        }

        Ok(Init {
            dsid,
            club_type,
            identifier: sections[0].clone(),
            salt: sections[1].clone(),
            server_public: sections[2].clone(),
            header,
        })
    }

    /// RECOVER: send the SRP proof and receive the encrypted record.
    pub async fn recover(&self, label: &str, init: &Init, proof: &[u8]) -> Result<Recovery> {
        let mut header = init.header.clone();
        header[0..4].copy_from_slice(&165u32.to_be_bytes());
        let version = if init.club_type == Some(1) {
            2u32
        } else {
            0u32
        };
        header[4..8].copy_from_slice(&version.to_be_bytes());

        let payload = pack(&header, &[(&init.identifier, 20), (proof, 0)])?;
        let mut request = Dictionary::new();
        request.insert("command".into(), Value::String("RECOVER".into()));
        request.insert("label".into(), Value::String(label.into()));
        request.insert("transactionUUID".into(), Value::String(uuid()));
        request.insert("userActionLabel".into(), Value::String(USER_ACTION.into()));
        request.insert("version".into(), Value::Integer(1.into()));
        request.insert(
            "blob".into(),
            Value::String(base64::engine::general_purpose::STANDARD.encode(payload)),
        );

        let response = self.invoke("recover", request).await?;
        let blob = response
            .get("respBlob")
            .and_then(Value::as_string)
            .ok_or_else(|| Error::Message("escrow did not return a response blob".into()))?;
        let blob = base64_decode(blob)?;
        let header_len = if init.club_type == Some(1) { 40 } else { 24 };
        let (header, sections) = unpack(&blob, header_len, 3)?;

        Ok(Recovery {
            m2: sections[0].clone(),
            header,
            sections,
        })
    }

    /// Run SRP_INIT and RECOVER and return the bottle entropy.
    ///
    /// This consumes one of the ten irreversible escrow attempts. The caller
    /// must have explicit confirmation.
    pub async fn entropy(&self, label: &str, passcode: &[u8], _adsid: &str) -> Result<Vec<u8>> {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let a = BigUint::from_bytes_be(&secret);
        let (public, _) = public_a(&a);
        let init = self.srp_init(label, &public).await?;

        let (m1, key) = proof(&a, &init.dsid, passcode, &init.salt, &init.server_public)?;
        let recovery = self.recover(label, &init, &m1).await?;
        let expected = server_proof(&public, &m1, &key);
        if recovery.m2 != expected {
            return Err(Error::Message(
                "escrow server proof did not verify; the passcode may be wrong".into(),
            ));
        }

        let version = be32(&recovery.header, 4)?;
        let plaintext = match version {
            0 => aes256_cbc_decrypt(&key, &recovery.sections[1], &recovery.sections[2])?,
            2 => aes_gcm_decrypt(&key, &recovery.sections[1], &recovery.sections[2], &[])?,
            other => {
                return Err(Error::Message(format!(
                    "unsupported escrow record version {other}"
                )))
            }
        };

        let (inner_header, inner) = unpack(&plaintext, 16, 6)?;
        let rounds = be32(&inner_header, 8)?;
        let salt = inner[1].clone();
        let iv = salt
            .get(..16)
            .ok_or_else(|| Error::Message("escrow salt is shorter than 16 bytes".into()))?;
        let derived = pbkdf2_sha256(passcode, &salt, rounds, 16)?;
        let bottle = aes_cbc_decrypt(&derived, iv, &inner[3])?;
        let value: Value = plist::from_bytes(&bottle)?;
        let entropy = value
            .as_dictionary()
            .and_then(|dict| dict.get("BottledPeerEntropy"))
            .and_then(Value::as_data)
            .ok_or_else(|| Error::Message("escrow record has no BottledPeerEntropy".into()))?;
        Ok(entropy.to_vec())
    }

    async fn invoke(&self, slug: &str, request: Dictionary) -> Result<Dictionary> {
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, &Value::Dictionary(request))?;

        let mut last_status = reqwest::StatusCode::UNAUTHORIZED;
        let mut last_value = Value::Dictionary(Dictionary::new());
        let candidates: [(&str, &str, &str); 9] = [
            (&self.email, &self.pet, "email:pet"),
            (&self.dsid, &self.pet, "dsid:pet"),
            (&self.adsid, &self.mme_token, "adsid:mme"),
            (&self.dsid, &self.mme_token, "dsid:mme"),
            (&self.email, &self.mme_token, "email:mme"),
            (&self.adsid, &self.pet, "adsid:pet"),
            (&self.dsid, &self.cloudkit_token, "dsid:ck"),
            (&self.email, &self.cloudkit_token, "email:ck"),
            (&self.adsid, &self.cloudkit_token, "adsid:ck"),
        ];
        for (user, secret, label) in candidates {
            if std::env::var_os("APW_DEBUG").is_some() {
                eprintln!(
                    "escrow auth: {label} user={user} secret_len={} slug={slug}",
                    secret.len()
                );
            }
            let response = self.send(slug, user, secret, &body).await?;
            let status = response.status();
            let bytes = response.bytes().await?.to_vec();
            let value: Value = plist::from_bytes(&bytes)
                .map_err(|error| Error::Message(format!("invalid escrow response: {error}")))?;
            if status.is_success() {
                return value
                    .as_dictionary()
                    .cloned()
                    .ok_or_else(|| Error::Message("escrow response is not a dictionary".into()));
            }
            if status != reqwest::StatusCode::UNAUTHORIZED {
                return Err(Error::Message(format!(
                    "escrowproxy/{slug} returned {status}: {value:?}"
                )));
            }
            last_status = status;
            last_value = value;
        }

        Err(Error::Message(format!(
            "escrowproxy/{slug} returned {last_status}: {last_value:?}"
        )))
    }

    async fn send(
        &self,
        slug: &str,
        user: &str,
        secret: &str,
        body: &[u8],
    ) -> Result<reqwest::Response> {
        let mut http = self
            .http
            .post(format!("{}/escrowproxy/api/{slug}", self.base))
            .basic_auth(user, Some(secret))
            .header("user-agent", ESCROW_USER_AGENT)
            .header("accept", "*/*")
            .header("accept-language", "en-US,en;q=0.9")
            .header("x-apple-i-locale", "en_US")
            .header("x-apple-i-device-type", "1")
            .header("content-type", "application/x-apple-plst")
            .header(
                "x-mme-client-info",
                anisette::with_service(&self.identity.client_info, anisette::SBD_SERVICE),
            )
            .header("x-apple-adsid", &self.adsid)
            .body(body.to_vec());

        for (name, value) in &self.identity.headers {
            if name.eq_ignore_ascii_case("x-mme-client-info") {
                continue;
            }
            http = http.header(name, value);
        }
        let request = http.build()?;
        if std::env::var_os("APW_DEBUG").is_some() {
            eprintln!(
                "escrow request: url={} headers={:?} body_len={}",
                request.url(),
                request.headers().keys().collect::<Vec<_>>(),
                body.len()
            );
        }
        Ok(self.http.execute(request).await?)
    }
}

/// Parse the bottles from a `fetchViableBottles` response.
pub fn parse_bottles(data: &[u8]) -> Result<Vec<Bottle>> {
    let mut reader = Reader::new(data);
    let mut out = Vec::new();
    while let Some(field) = reader.next()? {
        if field.number != 1 {
            continue;
        }
        let mut entry = field.message()?;
        let mut label = String::new();
        let mut bottle = None;
        while let Some(item) = entry.next()? {
            match item.number {
                1 => label = item.string()?.to_string(),
                2 => {
                    // EscrowData.bottle wraps the serialized OTBottle in field 2.
                    let mut wrapper = item.message()?;
                    while let Some(inner) = wrapper.next()? {
                        if inner.number == 2 {
                            bottle = Some(parse_bottle(inner.bytes()?)?);
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(mut bottle) = bottle {
            bottle.label = label;
            out.push(bottle);
        }
    }
    Ok(out)
}

fn parse_bottle(data: &[u8]) -> Result<Bottle> {
    let mut reader = Reader::new(data);
    let mut bottle = Bottle {
        label: String::new(),
        peer_id: String::new(),
        bottle_id: String::new(),
        ct: Vec::new(),
        tag: Vec::new(),
        iv: Vec::new(),
    };
    while let Some(field) = reader.next()? {
        match field.number {
            1 => bottle.peer_id = field.string()?.to_string(),
            2 => bottle.bottle_id = field.string()?.to_string(),
            12 => {
                let mut cipher = field.message()?;
                while let Some(item) = cipher.next()? {
                    match item.number {
                        1 => bottle.ct = item.bytes()?.to_vec(),
                        2 => bottle.tag = item.bytes()?.to_vec(),
                        3 => bottle.iv = item.bytes()?.to_vec(),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(bottle)
}

/// Decrypt a bottle into the sponsor's peer keys.
pub fn recover_identity(bottle: &Bottle, entropy: &[u8], adsid: &str) -> Result<Recovered> {
    let key = hkdf(entropy, adsid, HKDF_SYMMETRIC, 32)?;
    let plaintext = aes_gcm_decrypt(&key, &bottle.iv, &bottle.ct, &bottle.tag)?;

    let mut reader = Reader::new(&plaintext);
    let mut signing = Vec::new();
    let mut encryption = Vec::new();
    while let Some(field) = reader.next()? {
        match field.number {
            3 => signing = parse_private_key(field.bytes()?)?,
            4 => encryption = parse_private_key(field.bytes()?)?,
            _ => {}
        }
    }
    if signing.is_empty() || encryption.is_empty() {
        return Err(Error::Message("bottle has no peer keys".into()));
    }

    Ok(Recovered {
        peer_id: bottle.peer_id.clone(),
        keys: PeerKeys::from_x963(&signing, &encryption)?,
    })
}

fn parse_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Reader::new(data);
    while let Some(field) = reader.next()? {
        if field.number == 2 {
            return Ok(field.bytes()?.to_vec());
        }
    }
    Err(Error::Message("bottle key has no key data".into()))
}

fn public_a(a: &BigUint) -> (Vec<u8>, BigUint) {
    let n = srp::modulus();
    let value = BigUint::from(2u32).modpow(a, &n);
    (trim(&value), value)
}

fn proof(
    a: &BigUint,
    username: &str,
    password: &[u8],
    salt: &[u8],
    server_public: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let n = srp::modulus();
    let g = BigUint::from(2u32);
    let b = BigUint::from_bytes_be(server_public);
    if b.is_zero() || b >= n {
        return Err(Error::Message(
            "escrow sent an invalid SRP public key".into(),
        ));
    }

    let a_public = trim(&g.modpow(a, &n));
    let b_trim = trim(&b);
    let k = BigUint::from_bytes_be(&sha256(&[&pad(&n), &pad(&g)]));
    let x = BigUint::from_bytes_be(&sha256(&[
        salt,
        &sha256(&[username.as_bytes(), b":", password]),
    ]));
    let u = BigUint::from_bytes_be(&sha256(&[&a_public, &b_trim]));
    if u.is_zero() {
        return Err(Error::Message("escrow sent an invalid SRP scramble".into()));
    }

    let base = (&b + &n - (k * g.modpow(&x, &n)) % &n) % &n;
    let shared = base.modpow(&(a + &u * &x), &n);
    let key = sha256(&[&trim(&shared)]);

    let m1 = sha256(&[
        &xor(&sha256(&[&pad(&n)]), &sha256(&[&pad(&g)])),
        &sha256(&[username.as_bytes()]),
        salt,
        &a_public,
        &b_trim,
        &key,
    ]);
    Ok((m1, key))
}

fn server_proof(public: &[u8], m1: &[u8], key: &[u8]) -> Vec<u8> {
    sha256(&[public, m1, key])
}

fn hkdf(entropy: &[u8], adsid: &str, info: &[u8], length: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha384>::new(Some(adsid.as_bytes()), entropy);
    let mut out = vec![0u8; length];
    hk.expand(info, &mut out)
        .map_err(|_| Error::Message("HKDF output is too long".into()))?;
    Ok(out)
}

fn aes_gcm_decrypt(key: &[u8], iv: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::consts::{U12, U16, U32};
    use aes_gcm::aead::generic_array::GenericArray;

    let mut combined = ct.to_vec();
    combined.extend_from_slice(tag);
    let payload = Payload {
        msg: &combined,
        aad: &[],
    };

    // Apple uses both 12-byte and 16-byte GCM nonces.
    match iv.len() {
        12 => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::Message("invalid AES-256-GCM key".into()))?;
            cipher
                .decrypt(GenericArray::<u8, U12>::from_slice(iv), payload)
                .map_err(|_| {
                    Error::Message("bottle decrypt failed: wrong entropy or account".into())
                })
        }
        16 => {
            type Aes256Gcm16 = aes_gcm::AesGcm<aes::Aes256, U16>;
            let cipher = Aes256Gcm16::new_from_slice(key)
                .map_err(|_| Error::Message("invalid AES-256-GCM key".into()))?;
            cipher
                .decrypt(GenericArray::<u8, U16>::from_slice(iv), payload)
                .map_err(|_| {
                    Error::Message("bottle decrypt failed: wrong entropy or account".into())
                })
        }
        32 => {
            type Aes256Gcm32 = aes_gcm::AesGcm<aes::Aes256, U32>;
            let cipher = Aes256Gcm32::new_from_slice(key)
                .map_err(|_| Error::Message("invalid AES-256-GCM key".into()))?;
            cipher
                .decrypt(GenericArray::<u8, U32>::from_slice(iv), payload)
                .map_err(|_| {
                    Error::Message("bottle decrypt failed: wrong entropy or account".into())
                })
        }
        other => Err(Error::Message(format!(
            "unsupported AES-GCM nonce length {other}"
        ))),
    }
}

fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    type Decryptor = cbc::Decryptor<aes::Aes256>;
    let mut buffer = ct.to_vec();
    let plaintext = Decryptor::new_from_slices(key, iv)
        .map_err(|_| Error::Message("invalid AES-256-CBC key or IV".into()))?
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| Error::Message("escrow record padding is invalid".into()))?;
    Ok(plaintext.to_vec())
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    type Decryptor = cbc::Decryptor<Aes128>;
    let mut buffer = ct.to_vec();
    let plaintext = Decryptor::new_from_slices(key, iv)
        .map_err(|_| Error::Message("invalid AES-128-CBC key or IV".into()))?
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| Error::Message("escrow record padding is invalid".into()))?;
    Ok(plaintext.to_vec())
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32, len: usize) -> Result<Vec<u8>> {
    if rounds == 0 || rounds > 1_000_000 {
        return Err(Error::Message(format!(
            "escrow record has an invalid round count: {rounds}"
        )));
    }
    let mut out = vec![0u8; len];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, rounds, &mut out);
    Ok(out)
}

fn unpack(data: &[u8], header_len: usize, sections: usize) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    if data.len() < 4 + header_len + (sections + 1) * 4 {
        return Err(Error::Message("escrow message is too short".into()));
    }
    let header = data[4..4 + header_len].to_vec();
    let offsets = 4 + header_len;
    let body = offsets + (sections + 1) * 4;
    let mut out = Vec::with_capacity(sections);
    for index in 0..sections {
        let offset = be32(data, offsets + index * 4)? as usize;
        let start = body + offset;
        if start + 4 > data.len() {
            return Err(Error::Message("escrow section is out of range".into()));
        }
        let len = be32(data, start)? as usize;
        if start + 4 + len > data.len() {
            return Err(Error::Message("escrow section is truncated".into()));
        }
        out.push(data[start + 4..start + 4 + len].to_vec());
    }
    Ok((header, out))
}

fn pack(header: &[u8], sections: &[(&[u8], usize)]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut offsets = Vec::new();
    for (data, size) in sections {
        offsets.push(body.len() as u32);
        let mut section = (data.len() as u32).to_be_bytes().to_vec();
        section.extend_from_slice(data);
        if *size > 0 {
            if section.len() > *size {
                return Err(Error::Message("escrow section does not fit".into()));
            }
            section.resize(*size, 0);
        }
        body.extend_from_slice(&section);
    }
    offsets.push(body.len() as u32);

    let mut out = Vec::new();
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(header);
    for offset in offsets {
        out.extend_from_slice(&offset.to_be_bytes());
    }
    out.extend_from_slice(&body);
    let total = out.len() as u32;
    out[0..4].copy_from_slice(&total.to_be_bytes());
    Ok(out)
}

fn be32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| Error::Message("escrow message is truncated".into()))?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
}

fn trim(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.len() == 1 && bytes[0] == 0 {
        return vec![0];
    }
    bytes
}

fn pad(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let size = 256;
    if bytes.len() >= size {
        return bytes;
    }
    let mut out = vec![0u8; size - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

fn xor(left: &[u8], right: &[u8]) -> Vec<u8> {
    left.iter().zip(right).map(|(a, b)| a ^ b).collect()
}

fn uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = data_encoding::HEXUPPER.encode(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn base64_decode(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| Error::Message(format!("invalid base64 in escrow response: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Writer;
    use aes_gcm::Nonce;

    #[test]
    fn pack_unpack_round_trip() {
        let header = vec![7u8; 24];
        let packed = pack(&header, &[(b"id", 20), (b"proof", 0)]).unwrap();
        let (parsed, sections) = unpack(&packed, 24, 2).unwrap();
        assert_eq!(parsed, header);
        assert_eq!(sections[0], b"id");
        assert_eq!(sections[1], b"proof");
    }

    #[test]
    fn bottle_round_trip() {
        let keys = PeerKeys::generate();
        let entropy = [9u8; 72];
        let adsid = "1234";

        let mut internal = Writer::new();
        let mut signing = Writer::new();
        signing.uint64(1, 1).bytes(2, &keys.signing_x963());
        let mut encryption = Writer::new();
        encryption.uint64(1, 1).bytes(2, &keys.encryption_x963());
        internal.message(3, &signing);
        internal.message(4, &encryption);

        let key = hkdf(&entropy, adsid, HKDF_SYMMETRIC, 32).unwrap();
        let iv = [3u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let sealed = cipher
            .encrypt(Nonce::from_slice(&iv), internal.as_slice())
            .unwrap();
        let (ct, tag) = sealed.split_at(sealed.len() - 16);

        let bottle = Bottle {
            label: "record".into(),
            peer_id: "SHA256:test".into(),
            bottle_id: "bottle".into(),
            ct: ct.to_vec(),
            tag: tag.to_vec(),
            iv: iv.to_vec(),
        };
        let recovered = recover_identity(&bottle, &entropy, adsid).unwrap();
        assert_eq!(recovered.peer_id, "SHA256:test");
        assert_eq!(recovered.keys.signing_x963(), keys.signing_x963());
    }
}
