//! Native Apple device identity (ADI, also called anisette).
//!
//! This is a translation of the ADI implementation in
//! [`apple-auth`](https://github.com/apple-auth/apple-auth), which is MIT
//! licensed, Copyright (c) 2026 yummy1gay. The notice is in `LICENSE-MIT`.
//! No Apple binary is loaded, emulated, or downloaded.

use base64::Engine as _;

mod crypto;
mod data;
mod gsa;
mod mac;
mod otp;
mod provisioning;
mod tables;

pub use provisioning::{Entropy, Provisioning};

/// Apple advances the ADI counter once per 30 seconds of UTC time.
pub const OTP_WINDOW_SECONDS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Mac = 1,
    Windows = 2,
}

impl Platform {
    pub const fn id(self) -> u32 {
        self as u32
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Mac => "macos",
            Self::Windows => "windows",
        }
    }

    pub const fn secondary_len(self) -> usize {
        match self {
            Self::Mac => 400,
            Self::Windows => 208,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid ADI data: {0}")]
    Invalid(&'static str),
    #[error("ADI provisioning is already complete")]
    Finished,
}

pub type Result<T> = std::result::Result<T, Error>;

/// A provisioned GrandSlam ADI profile.
///
/// The seed and device key are derived once and wiped when the profile drops.
#[derive(Clone)]
pub struct Profile {
    pub machine_id: [u8; 60],
    pub secondary: Vec<u8>,
    pub encrypted_seed: [u8; 32],
    pub extra_data: [u8; 8],
    pub option: Option<u32>,
    pub platform: Platform,
    seed: [u8; 32],
    key: [u8; 16],
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Profile")
            .field("platform", &self.platform)
            .field("machine_id_len", &self.machine_id.len())
            .field("secondary_len", &self.secondary.len())
            .finish_non_exhaustive()
    }
}

impl Profile {
    pub fn from_parts(
        machine_id: [u8; 60],
        secondary: Vec<u8>,
        encrypted_seed: [u8; 32],
        extra_data: [u8; 8],
        option: Option<u32>,
        platform: Platform,
    ) -> Result<Self> {
        if secondary.len() != platform.secondary_len() {
            return Err(Error::Invalid("secondary state has the wrong length"));
        }
        let seed = otp::decode_seed(&encrypted_seed)?;
        let key = otp::decode_device_key(platform, &secondary)?;
        Ok(Self {
            machine_id,
            secondary,
            encrypted_seed,
            extra_data,
            option,
            platform,
            seed,
            key,
        })
    }

    /// The 16-byte ADI proof for a 30-second counter.
    pub fn otp(&self, counter: u32) -> [u8; 16] {
        otp::generate(self.platform, &self.seed, counter, &self.key)
    }

    /// The 28-byte `X-Apple-I-MD` envelope: version 5, length 16, proof,
    /// and the platform trailer.
    pub fn otp_envelope(&self, counter: u32) -> [u8; 28] {
        let mut envelope = [0_u8; 28];
        envelope[3] = 5;
        envelope[7] = 16;
        envelope[8..24].copy_from_slice(&self.otp(counter));
        envelope[27] = self.platform.id() as u8;
        envelope
    }

    pub fn otp_header(&self, counter: u32) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.otp_envelope(counter))
    }

    pub fn machine_id_header(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.machine_id)
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        for byte in self.seed.iter_mut().chain(self.key.iter_mut()) {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

/// Apple's counter for a Unix timestamp.
pub fn time_counter(unix_seconds: i64) -> Result<u32> {
    if unix_seconds < 0 {
        return Err(Error::Invalid("negative Unix time"));
    }
    u32::try_from(unix_seconds as u64 / OTP_WINDOW_SECONDS)
        .map_err(|_| Error::Invalid("Unix time is out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        let bytes = HEXLOWER.decode(value.as_bytes()).unwrap();
        bytes.try_into().unwrap()
    }

    fn base64(value: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .unwrap()
    }

    #[test]
    fn matches_reference_vectors() {
        let document: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/adi/profiles.json")).unwrap();
        let counters: Vec<u32> = document["counters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u32)
            .collect();
        for (name, device) in document["devices"].as_object().unwrap() {
            let platform = match device["identity"]["platform"].as_str().unwrap() {
                "mac" => Platform::Mac,
                "windows" => Platform::Windows,
                other => panic!("{name}: unknown platform {other}"),
            };
            let profile = Profile::from_parts(
                hex(device["profile"]["profile_data"].as_str().unwrap()),
                base64(device["profile"]["secondary"].as_str().unwrap()),
                hex(device["profile"]["encrypted_seed"].as_str().unwrap()),
                hex(device["profile"]["extra_data"].as_str().unwrap()),
                device["profile"]["option"]
                    .as_u64()
                    .map(|value| value as u32),
                platform,
            )
            .unwrap();
            assert_eq!(
                profile.machine_id_header(),
                device["vectors"]["machine_id"].as_str().unwrap(),
                "{name}: machine ID"
            );
            for counter in &counters {
                assert_eq!(
                    profile.otp_header(*counter),
                    device["vectors"]["otp"][counter.to_string()]
                        .as_str()
                        .unwrap(),
                    "{name}: counter {counter}"
                );
            }
        }
    }
}
