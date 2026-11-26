//! Fixed ADI algorithm parameters recovered by the apple-auth project.

use super::tables;

/// The reference stores its tables behind a xorshift32 byte stream so that the
/// decoded constants never appear in the binary image.
struct Stream(u32);

impl Stream {
    fn next(&mut self) -> u32 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        self.0 = value;
        value
    }
}

fn unmask_u8<const N: usize>(masked: &[u8; N], seed: u32) -> [u8; N] {
    let mut stream = Stream(seed);
    let mut output = *masked;
    for value in output.iter_mut() {
        *value ^= stream.next() as u8;
    }
    output
}

fn unmask_u16<const N: usize>(masked: &[u16; N], seed: u32) -> [u16; N] {
    let mut stream = Stream(seed);
    let mut output = *masked;
    for value in output.iter_mut() {
        *value ^= stream.next() as u16;
    }
    output
}

fn unmask_u32<const N: usize>(masked: &[u32; N], seed: u32) -> [u32; N] {
    let mut stream = Stream(seed);
    let mut output = *masked;
    for value in output.iter_mut() {
        *value ^= stream.next();
    }
    output
}

fn bytes_at<const N: usize>(source: &[u8], offset: usize) -> [u8; N] {
    std::array::from_fn(|index| source[offset + index])
}

pub struct SeedCipher {
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

pub struct SecondaryCipher {
    pub key: [u8; 16],
    pub iv: [u8; 16],
    pub whitening: [u8; 16],
    pub output_maps: [[u8; 8]; 4],
}

pub struct GsaMixedKey {
    /// Three state offsets per round-key byte: direct, then two sharing a map.
    pub sources: [[u8; 3]; 16],
    pub offsets: [u8; 16],
    pub mapped_sources: [u8; 8],
}

// Offsets into the decoded 276-byte GrandSlam state block.
const STATE_BODY_KEY_LEN: usize = 48;
const STATE_FIELD_MASK_LEN: usize = 16;
const STATE_OUTER_TAG_LEN: usize = 4;
const STATE_RECORD_TAGS_LEN: usize = 24;
const STATE_SEED_KEY: usize =
    STATE_BODY_KEY_LEN + STATE_FIELD_MASK_LEN + STATE_OUTER_TAG_LEN + STATE_RECORD_TAGS_LEN;
const STATE_SEED_IV: usize = STATE_SEED_KEY + 16;
const STATE_SECONDARY_KEY: usize = STATE_SEED_IV + 16;
const STATE_SECONDARY_IV: usize = STATE_SECONDARY_KEY + 16;
const STATE_SECONDARY_WHITENING: usize = STATE_SECONDARY_IV + 16;
const STATE_SECONDARY_MAPS: usize = STATE_SECONDARY_WHITENING + 16;
const STATE_MIXED_SOURCES: usize = STATE_SECONDARY_MAPS + 32;
const STATE_MIXED_OFFSETS: usize = STATE_MIXED_SOURCES + 48;
const STATE_MIXED_MAP: usize = STATE_MIXED_OFFSETS + 16;

fn state_block() -> [u8; 276] {
    unmask_u8(&tables::STATE_DATA, tables::STATE_DATA_SEED)
}

pub fn seed_cipher() -> SeedCipher {
    let state = state_block();
    SeedCipher {
        key: bytes_at(&state, STATE_SEED_KEY),
        iv: bytes_at(&state, STATE_SEED_IV),
    }
}

fn secondary_cipher(source: &[u8], key: usize) -> SecondaryCipher {
    SecondaryCipher {
        key: bytes_at(source, key),
        iv: bytes_at(source, key + 16),
        whitening: bytes_at(source, key + 32),
        output_maps: std::array::from_fn(|map| bytes_at(source, key + 48 + map * 8)),
    }
}

pub fn gsa_secondary_cipher() -> SecondaryCipher {
    secondary_cipher(&state_block(), STATE_SECONDARY_KEY)
}

pub fn gsa_mixed_key() -> GsaMixedKey {
    let state = state_block();
    GsaMixedKey {
        sources: std::array::from_fn(|index| bytes_at(&state, STATE_MIXED_SOURCES + index * 3)),
        offsets: bytes_at(&state, STATE_MIXED_OFFSETS),
        mapped_sources: bytes_at(&state, STATE_MIXED_MAP),
    }
}

pub fn mac_secondary_cipher() -> SecondaryCipher {
    let masked = unmask_u8(
        &tables::MAC_SECONDARY_CIPHER,
        tables::MAC_SECONDARY_CIPHER_SEED,
    );
    secondary_cipher(&masked, 0)
}

pub fn mac_mixing_positions() -> [u16; 384] {
    unmask_u16(
        &tables::MAC_MIXING_POSITIONS,
        tables::MAC_MIXING_POSITIONS_SEED,
    )
}

pub fn mac_key_sources() -> [[u16; 4]; 16] {
    let decoded = unmask_u16(&tables::MAC_KEY_SOURCES, tables::MAC_KEY_SOURCES_SEED);
    std::array::from_fn(|index| std::array::from_fn(|position| decoded[index * 4 + position]))
}

pub fn mac_key_offsets() -> [u8; 16] {
    unmask_u8(&tables::MAC_KEY_OFFSETS, tables::MAC_KEY_OFFSETS_SEED)
}

pub fn mac_key_map() -> [u8; 8] {
    unmask_u8(&tables::MAC_KEY_MAP, tables::MAC_KEY_MAP_SEED)
}

pub fn mac_hash_initial_state() -> [u32; 8] {
    unmask_u32(
        &tables::MAC_HASH_INITIAL_STATE,
        tables::MAC_HASH_INITIAL_STATE_SEED,
    )
}

pub fn mac_hash_round_constants() -> [u32; 64] {
    unmask_u32(
        &tables::MAC_HASH_ROUND_CONSTANTS,
        tables::MAC_HASH_ROUND_CONSTANTS_SEED,
    )
}

pub fn gsa_key_mix_positions() -> [u8; 192] {
    unmask_u8(
        &tables::GSA_KEY_MIX_POSITIONS,
        tables::GSA_KEY_MIX_POSITIONS_SEED,
    )
}

pub fn gsa_hash_initial_state() -> [u32; 8] {
    unmask_u32(
        &tables::GSA_HASH_INITIAL_STATE,
        tables::GSA_HASH_INITIAL_STATE_SEED,
    )
}

pub fn gsa_hash_round_constants() -> [u32; 64] {
    unmask_u32(
        &tables::GSA_HASH_ROUND_CONSTANTS,
        tables::GSA_HASH_ROUND_CONSTANTS_SEED,
    )
}

pub fn counter_moduli() -> [u32; 4] {
    unmask_u32(&tables::COUNTER_MODULI, tables::COUNTER_MODULI_SEED)
}
