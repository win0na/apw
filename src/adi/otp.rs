//! ADI seed decryption, device-key recovery, and the 30-second proof.

use super::{crypto, data, gsa, mac, Error, Platform, Result};

pub fn decode_seed(ciphertext: &[u8; 32]) -> Result<[u8; 32]> {
    let parameters = data::seed_cipher();
    let cipher = crypto::cipher(&parameters.key);
    let mut seed = [0_u8; 32];
    let mut previous = parameters.iv;
    for offset in (0..seed.len()).step_by(16) {
        let mut block = [0_u8; 16];
        block.copy_from_slice(&ciphertext[offset..offset + 16]);
        let plaintext = crypto::decrypt_block(&cipher, &block);
        for index in 0..16 {
            seed[offset + index] = plaintext[index] ^ previous[index];
        }
        previous = block;
    }
    Ok(seed)
}

pub fn decode_device_key(platform: Platform, secondary: &[u8]) -> Result<[u8; 16]> {
    match platform {
        Platform::Mac => {
            let state: [u8; 400] = secondary
                .try_into()
                .map_err(|_| Error::Invalid("secondary state has the wrong length"))?;
            Ok(mac::decode_device_key(&state))
        }
        Platform::Windows => {
            let state: [u8; 208] = secondary
                .try_into()
                .map_err(|_| Error::Invalid("secondary state has the wrong length"))?;
            Ok(gsa::decode_device_key(&state))
        }
    }
}

fn hash(platform: Platform, message: &[u8]) -> [u8; 32] {
    match platform {
        Platform::Mac => mac::hash(message),
        Platform::Windows => gsa::hash(message),
    }
}

pub fn generate(platform: Platform, seed: &[u8; 32], counter: u32, key: &[u8; 16]) -> [u8; 16] {
    let seed_hash = hash(platform, seed);
    let expanded_hash = hash(platform, &crypto::expand_digest(&seed_hash));
    let counter_hash = hash(platform, &crypto::counter_message(seed, counter));
    crypto::compute_otp_mac(&[seed_hash, expanded_hash, counter_hash], key)
}
