//! AES-128 primitives, byte maps, and the digest plumbing shared by the ADI
//! state, OTP, and provisioning code.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

use super::data::SecondaryCipher;

/// The AES S-box, derived at compile time from the field inverse.
const SBOX: [u8; 256] = {
    let mut table = [0_u8; 256];
    let mut index = 0;
    while index < table.len() {
        table[index] = sbox_byte(index as u8);
        index += 1;
    }
    table
};

const fn gf_multiply(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0_u8;
    while right != 0 {
        if right & 1 != 0 {
            result ^= left;
        }
        let high_bit = left & 0x80 != 0;
        left <<= 1;
        if high_bit {
            left ^= 0x1B;
        }
        right >>= 1;
    }
    result
}

const fn gf_inverse(value: u8) -> u8 {
    if value == 0 {
        return 0;
    }
    let mut inverse = 1_u8;
    let mut power = value;
    let mut exponent = 254_u32;
    while exponent != 0 {
        if exponent & 1 != 0 {
            inverse = gf_multiply(inverse, power);
        }
        power = gf_multiply(power, power);
        exponent >>= 1;
    }
    inverse
}

const fn sbox_byte(value: u8) -> u8 {
    let inverse = gf_inverse(value);
    let mut result = inverse ^ 0x63;
    let mut rotation = 1_u32;
    while rotation < 5 {
        result ^= inverse.rotate_left(rotation);
        rotation += 1;
    }
    result
}

pub fn cipher(key: &[u8; 16]) -> Aes128 {
    Aes128::new(GenericArray::from_slice(key))
}

pub fn encrypt_block(cipher: &Aes128, block: &[u8; 16]) -> [u8; 16] {
    let mut state = aes::Block::from(*block);
    cipher.encrypt_block(&mut state);
    state.into()
}

pub fn decrypt_block(cipher: &Aes128, block: &[u8; 16]) -> [u8; 16] {
    let mut state = aes::Block::from(*block);
    cipher.decrypt_block(&mut state);
    state.into()
}

/// Invert the AES-128 key schedule from the final round key back to the cipher
/// key. The ADI decoders only expose the last round key.
pub fn recover_aes128_key(mut current: [u8; 16]) -> [u8; 16] {
    const ROUND_CONSTANTS: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
    for round in (1..=ROUND_CONSTANTS.len()).rev() {
        let mut previous = [0_u8; 16];
        for byte in 4..16 {
            previous[byte] = current[byte] ^ current[byte - 4];
        }
        let transformed = [
            SBOX[previous[13] as usize] ^ ROUND_CONSTANTS[round - 1],
            SBOX[previous[14] as usize],
            SBOX[previous[15] as usize],
            SBOX[previous[12] as usize],
        ];
        for byte in 0..4 {
            previous[byte] = current[byte] ^ transformed[byte];
        }
        current = previous;
    }
    current
}

/// Apply one of the recovered 8x8 GF(2) linear maps to a byte.
pub fn apply_linear_map(map: &[u8; 8], value: u8) -> u8 {
    let mut result = 0_u8;
    for (bit, basis) in map.iter().enumerate() {
        if value & (1 << bit) != 0 {
            result ^= basis;
        }
    }
    result
}

/// CBC-style unwrap of an opaque secondary state: each plaintext block is
/// XORed with the previous ciphertext block and the fixed whitening, then
/// passed through the four output maps. `output[index % 4]` is used as-is, as
/// the Mac variant does; the store variant's byte swap is a different mode.
pub fn decode_secondary<const N: usize>(
    ciphertext: &[u8; N],
    parameters: &SecondaryCipher,
) -> [u8; N] {
    let cipher = cipher(&parameters.key);
    let mut output = [0_u8; N];
    let mut previous = parameters.iv;
    for offset in (0..N).step_by(16) {
        let mut block = [0_u8; 16];
        block.copy_from_slice(&ciphertext[offset..offset + 16]);
        let plaintext = decrypt_block(&cipher, &block);
        for index in 0..16 {
            let value = plaintext[index] ^ previous[index] ^ parameters.whitening[index];
            output[offset + index] = apply_linear_map(&parameters.output_maps[index % 4], value);
        }
        previous = block;
    }
    output
}

/// The ADI proof: three 32-byte hashes are folded through AES-128 in ECB mode.
pub fn compute_otp_mac(hashes: &[[u8; 32]; 3], key: &[u8; 16]) -> [u8; 16] {
    let cipher = cipher(key);
    let mut state = [0_u8; 16];
    for hash in hashes {
        for offset in (0..32).step_by(16) {
            for byte in 0..16 {
                state[byte] ^= hash[offset + byte];
            }
            state = encrypt_block(&cipher, &state);
        }
    }
    state
}

/// Fixed diffusion step shared by the Mac and GrandSlam hash families.
pub fn expand_digest(digest: &[u8; 32]) -> [u8; 64] {
    std::array::from_fn(|index| {
        let left = (5 * index + 7) % digest.len();
        let right = (5 * index * index + 9) % digest.len();
        digest[left] ^ digest[right].wrapping_add(42)
    })
}

/// Encode the counter into the 55-byte message consumed by the OTP hashes.
pub fn counter_message(seed: &[u8; 32], counter: u32) -> [u8; 55] {
    let moduli = super::data::counter_moduli();
    let mut message = [0_u8; 55];
    for (index, modulus) in moduli.iter().enumerate() {
        let remainder = counter % modulus;
        message[index * 2] = (remainder >> 8) as u8;
        message[index * 2 + 1] = remainder as u8;
    }
    let mut rolling: u32 = 0x6B53_2D89;
    for index in 0..seed.len() * 3 {
        let destination = (index + 7) % message.len();
        let mixed = ((rolling as u8) ^ 0x1A).wrapping_add(seed[(index * 2 + 1) % seed.len()]);
        message[destination] ^= mixed;
        rolling ^= (message[destination] as u32).wrapping_mul(0x5D80_9044);
    }
    message
}

/// Merkle-Damgard padding and length suffix shared by the three ADI hashes.
pub fn hash_message(
    message: &[u8],
    initial: [u32; 8],
    mut compress: impl FnMut([u32; 8], &[u8; 64]) -> [u32; 8],
) -> [u8; 32] {
    let mut state = initial;
    let complete = message.len() - message.len() % 64;
    let mut block = [0_u8; 64];
    for chunk in message[..complete].as_chunks::<64>().0 {
        state = compress(state, chunk);
    }

    let remaining = message.len() - complete;
    let mut tail = [0_u8; 128];
    tail[..remaining].copy_from_slice(&message[complete..]);
    tail[remaining] = 0x80;
    let padded = if remaining < 56 { 64 } else { 128 };
    let bit_length = (message.len() as u64) * 8;
    tail[padded - 8..padded].copy_from_slice(&bit_length.to_be_bytes());
    for offset in (0..padded).step_by(64) {
        block.copy_from_slice(&tail[offset..offset + 64]);
        state = compress(state, &block);
    }

    let mut digest = [0_u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}
