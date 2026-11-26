//! macOS ADI device-key decoding and hash.

use super::{crypto, data};

const STATE_LEN: usize = 400;

fn mix_key_state(input: &[u8; STATE_LEN]) -> [u8; STATE_LEN] {
    let mut state = *input;
    for value in state.iter_mut() {
        *value ^= 0x4D;
    }
    let mut feedback = state[14]
        .wrapping_add(state[292])
        .wrapping_add(state[290])
        .wrapping_add(state[319]);
    state[108] = state[108].wrapping_sub(feedback);
    for destination in data::mac_mixing_positions() {
        let destination = destination as usize;
        let value = state[destination];
        state[destination] = match feedback & 7 {
            0 => value.wrapping_sub(feedback),
            1 => value.wrapping_add(feedback),
            2 | 3 => value ^ feedback,
            _ => value,
        };
        feedback = (feedback ^ state[destination]).wrapping_add(0x12);
    }
    for value in state.iter_mut() {
        *value ^= 0x4D;
    }
    state
}

fn final_round_key(mixed: &[u8; STATE_LEN]) -> [u8; 16] {
    let map = data::mac_key_map();
    let mut key = data::mac_key_offsets();
    let sources = data::mac_key_sources();
    for index in 0..key.len() {
        let source = &sources[index];
        let encoded =
            mixed[source[1] as usize] ^ mixed[source[2] as usize] ^ mixed[source[3] as usize];
        key[index] ^= mixed[source[0] as usize] ^ crypto::apply_linear_map(&map, encoded);
    }
    key
}

pub fn decode_device_key(opaque_state: &[u8; STATE_LEN]) -> [u8; 16] {
    let decoded = crypto::decode_secondary(opaque_state, &data::mac_secondary_cipher());
    let mixed = mix_key_state(&decoded);
    crypto::recover_aes128_key(final_round_key(&mixed))
}

fn round([a, b, c, d, e, f, g, h]: [u32; 8], message: u32, constant: u32) -> [u32; 8] {
    let sigma_e = e
        .rotate_right(6)
        .wrapping_sub(e.rotate_right(11))
        .wrapping_add(e.rotate_right(25));
    let first = (sigma_e ^ h)
        .wrapping_add(g.wrapping_mul(2))
        .wrapping_sub(e)
        .wrapping_sub(f ^ e)
        .wrapping_add(constant)
        .wrapping_sub(message);
    let mixed_abc = (a ^ b).wrapping_sub(a ^ c).wrapping_add(c).wrapping_sub(b);
    let second = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22) ^ mixed_abc;
    [
        first.wrapping_add(second),
        a,
        b,
        c,
        d.wrapping_add(first),
        e,
        f,
        g,
    ]
}

fn schedule_word(oldest: u32, fifteen: u32, seven: u32, two: u32) -> u32 {
    let first = (fifteen.rotate_right(7) ^ fifteen.rotate_right(18)).wrapping_sub(fifteen >> 3);
    let second = two.rotate_right(17) ^ two.rotate_right(19) ^ (two >> 10);
    oldest.wrapping_add(first ^ seven ^ second)
}

fn compress(initial: [u32; 8], block: &[u8; 64], constants: &[u32; 64]) -> [u32; 8] {
    let mut words = [0_u32; 64];
    for (index, word) in words[..16].iter_mut().enumerate() {
        *word = u32::from_be_bytes([
            block[index * 4],
            block[index * 4 + 1],
            block[index * 4 + 2],
            block[index * 4 + 3],
        ]);
    }
    for index in 16..words.len() {
        words[index] = schedule_word(
            words[index - 16],
            words[index - 15],
            words[index - 7],
            words[index - 2],
        );
    }
    let mut state = initial;
    for (index, word) in words.iter().enumerate() {
        state = round(state, *word, constants[index]);
    }
    [
        state[0].wrapping_sub(initial[0]),
        state[1] ^ initial[1],
        state[2].wrapping_sub(initial[2]),
        state[3] ^ initial[3],
        state[4].wrapping_add(initial[4]),
        state[5] ^ initial[5],
        state[6].wrapping_sub(initial[6]),
        state[7].wrapping_sub(initial[7]),
    ]
}

pub fn hash(message: &[u8]) -> [u8; 32] {
    let constants = data::mac_hash_round_constants();
    crypto::hash_message(message, data::mac_hash_initial_state(), |state, block| {
        compress(state, block, &constants)
    })
}
