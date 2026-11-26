//! GrandSlam (Windows) ADI device-key decoding and hash.

use super::{crypto, data};

const STATE_LEN: usize = 208;

fn mix_key_state(input: &[u8; STATE_LEN]) -> [u8; STATE_LEN] {
    let mut state = *input;
    for value in state.iter_mut() {
        *value ^= 5;
    }
    let mut feedback = state[207]
        .wrapping_add(state[147])
        .wrapping_add(state[8])
        .wrapping_add(state[123]);
    state[31] = state[31].wrapping_sub(feedback);
    for destination in data::gsa_key_mix_positions() {
        let destination = destination as usize;
        let value = state[destination];
        state[destination] = match feedback & 7 {
            3 => value.wrapping_sub(feedback),
            5 => value.wrapping_add(feedback),
            6 | 7 => value ^ feedback,
            _ => value,
        };
        feedback = (feedback ^ state[destination]).wrapping_add(0x6E);
    }
    for value in state.iter_mut() {
        *value ^= 5;
    }
    state
}

fn final_round_key(mixed: &[u8; STATE_LEN]) -> [u8; 16] {
    let parameters = data::gsa_mixed_key();
    let mut key = [0_u8; 16];
    for (index, byte) in key.iter_mut().enumerate() {
        let source = &parameters.sources[index];
        let encoded = mixed[source[1] as usize] ^ mixed[source[2] as usize];
        *byte = parameters.offsets[index]
            ^ mixed[source[0] as usize]
            ^ crypto::apply_linear_map(&parameters.mapped_sources, encoded);
    }
    key
}

pub fn decode_device_key(opaque_state: &[u8; STATE_LEN]) -> [u8; 16] {
    let decoded = crypto::decode_secondary(opaque_state, &data::gsa_secondary_cipher());
    let mixed = mix_key_state(&decoded);
    crypto::recover_aes128_key(final_round_key(&mixed))
}

fn round([a, b, c, d, e, f, g, h]: [u32; 8], message: u32, constant: u32) -> [u32; 8] {
    let sigma_a = a
        .rotate_right(2)
        .wrapping_add(a.rotate_right(13))
        .wrapping_sub(a.rotate_right(22));
    let mixed_abc = (a ^ b).wrapping_sub(a ^ c).wrapping_sub(b).wrapping_sub(c);
    let sigma_e = (e.rotate_right(6).wrapping_sub(e.rotate_right(11))) ^ e.rotate_right(25);
    let mixed_efg = ((f.wrapping_add(e)) ^ e ^ g).wrapping_add(g);
    let first = (h
        .wrapping_add(sigma_e)
        .wrapping_sub(mixed_efg)
        .wrapping_add(constant))
        ^ message;
    let second = sigma_a ^ mixed_abc;
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
    let first = fifteen
        .rotate_right(7)
        .wrapping_sub(fifteen.rotate_right(18))
        .wrapping_sub(fifteen >> 3);
    let second = (two.rotate_right(17) ^ two.rotate_right(19)).wrapping_add(two >> 10);
    first.wrapping_sub(second).wrapping_sub(seven) ^ oldest
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
        state[1].wrapping_add(initial[1]),
        state[2] ^ initial[2],
        state[3] ^ initial[3],
        state[4].wrapping_sub(initial[4]),
        state[5].wrapping_sub(initial[5]),
        state[6].wrapping_sub(initial[6]),
        state[7].wrapping_add(initial[7]),
    ]
}

pub fn hash(message: &[u8]) -> [u8; 32] {
    let constants = data::gsa_hash_round_constants();
    crypto::hash_message(message, data::gsa_hash_initial_state(), |state, block| {
        compress(state, block, &constants)
    })
}
