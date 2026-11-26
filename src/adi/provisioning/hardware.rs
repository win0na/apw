//! ADI provisioning hardware diffusion.
//!
//! The reference derives a 20-byte device tag from the hardware hash with two
//! fixed diffusion passes: a seed pass and a mixer pass, each finishing with a
//! block of table-driven byte adjustments. The expression structure follows the
//! reference so the wrapping semantics match; the working tables are
//! stream-masked constants.

use sha1::{Digest, Sha1};

use super::crypto;
use super::params::{
    unmask_u8, MIXER_WORKING_BASE, MIXER_WORKING_BASE_SEED, SEED_WORKING_BASE,
    SEED_WORKING_BASE_SEED,
};

const STATE_LEN: usize = 384;

fn add_wrapped(output: &mut [u8], index: usize, delta: u8) {
    let target = index % output.len();
    output[target] = output[target].wrapping_add(delta);
}

fn fold_tables(output: &mut [u8], working: &[u8; 64], local: &[u8; 64]) {
    for index in 0..working.len() {
        let target = index % output.len();
        output[target] ^= working[index] ^ local[index];
    }
}

fn cube_byte(value: u8) -> u8 {
    (value as u32 * value as u32 * value as u32) as u8
}

fn xor_shifts(value: u32, left: u32, right: u32) -> u8 {
    ((value << left) ^ (value >> right)) as u8
}

/// Labelled truncating cast, used to keep the long expressions readable.
fn byte(value: u32) -> u8 {
    value as u8
}

/// `(index - distance) % size` with the 32-bit wrapping the reference uses.
fn wrapped_index(index: usize, distance: u32, size: usize) -> usize {
    (index as u32).wrapping_sub(distance) as usize % size
}

/// `(index + size - distance % size) % size`.
fn previous_index(index: usize, distance: usize, size: usize) -> usize {
    (index + size - distance % size) % size
}

fn adjust_mixer(state: &mut [u8; STATE_LEN], output: &mut [u8], parameters: &[u8; 128]) {
    assert!(!output.is_empty(), "empty provisioning adjustment output");
    let initial = *state;
    let mut working = unmask_u8(&MIXER_WORKING_BASE, MIXER_WORKING_BASE_SEED);
    let mut local = [0_u8; 64];
    let mut fixed = [0_u8; 64];
    for index in 0..local.len() {
        local[index] = parameters[64 + index] ^ 0x7D;
        fixed[index] = parameters[index].wrapping_add(0xBA);
    }
    working[26] = initial[54] ^ 0x73;
    working[40] = 0xFA;
    local[25] = 0x4B;
    local[47] = byte(
        ((((local[initial[144] as usize & 0x3F] & 0xEE) ^ 0xFE) as u32).wrapping_add(0x15)) ^ 0xCA,
    );
    local[58] = 0_u32.wrapping_sub(initial[97] as u32).wrapping_add(0xE8) as u8;
    state[227] = initial[63];
    #[allow(clippy::identity_op)]
    let masked = ((0xED_u32 ^ 0xFF) & 0xC9) | (0xED & (initial[148] as u32 + 0x6B));
    local[26] =
        byte((((0_u32.wrapping_sub(masked).wrapping_add(0x31)) ^ 0x7D).wrapping_add(0x80)) ^ 0x7D);
    state[34] = working[initial[28] as usize & 0x3F]
        .wrapping_add(initial[34])
        .wrapping_add(0x4B);
    local[8] =
        !(fixed[initial[41] as usize & 0x3F] | 0xED) | (((0x8E_u32 * 0xFD) + 0xBA) & 0xEC) as u8;
    let rotation_source = fixed[initial[191] as usize & 0x3F];
    let table_2_left = working[initial[103] as usize & 0x3F];
    let table_2_right = working[initial[24] as usize & 0x3F];
    let product_left = initial[80] as u32 * table_2_left as u32;
    let product_right = table_2_right as u32 * 0x9A;
    working[2] =
        byte(((product_left & product_right) | (product_right & 0x76)) | (product_left & 0x76));
    state[199] = initial[199]
        .wrapping_sub((initial[178] & 0xA5) | (((initial[114] as u32 * 3) & 0x5A) as u8));
    working[38] = 0x41_u8.wrapping_add(fixed[initial[29] as usize & 0x3F]);
    state[95] = initial[95].wrapping_sub(local[initial[5] as usize & 0x3F]);
    working[15] = byte(
        0xEB_u32
            .wrapping_add(2 * working[initial[52] as usize & 0x3F] as u32)
            .wrapping_sub(cube_byte(initial[54]) as u32),
    );
    working[10] = initial[148].wrapping_add(0x4D) ^ 0x80;
    working[50] = 0x42;
    let table_11_lookup = working[initial[184] as usize & 0x3F];
    let table_11_shift = working[initial[65] as usize & 0x3F];
    let squared_source = (local[58] & 0x6D) ^ 0x92;
    local[14] = byte(squared_source as u32 * squared_source as u32 + 0x26);
    local[28] =
        (initial[158] & local[initial[37] as usize & 0x3F]).wrapping_sub(initial[51]) ^ 0xAD;
    local[11] = xor_shifts(
        table_11_lookup as u32 & 0x81,
        (table_11_shift as u32 & 4) ^ 5,
        (table_11_shift as u32 & 4) ^ 3,
    );
    let output_2_shift = working[initial[109] as usize & 0x3F];
    let majority_left = fixed[initial[245] as usize & 0x3F];
    let majority_right = fixed[initial[45] as usize & 0x3F];
    local[62] =
        byte((((initial[69] as u32 + 0x80) & 0x10) | ((initial[112] as u32 * 2) & 0x6C)) ^ 0x6B);
    let state_24_mask = local[initial[24] as usize & 0x3F];
    let lookup_bias = byte(
        0_u32
            .wrapping_sub(rotation_source as u32 >> 1)
            .wrapping_add(rotation_source as u32 & 0x36)
            .wrapping_add(0x64),
    );
    let rotated_bits = byte(
        ((initial[162] as u32 & rotation_source.rotate_left(7) as u32)
            | ((initial[162] | lookup_bias) as u32 & 0x18))
            ^ 0x63,
    );
    let state_24_lookup = fixed[rotated_bits as usize & 0x3F];
    working[42] = 0x96;
    state[24] =
        byte((state_24_lookup | 0xCD) as u32 ^ ((state_24_mask ^ 0x7D) as u32 & 0x47) ^ 0xE5);
    let state_95_bits = byte(((initial[95] & 0x16) ^ 0x31) as u32 + 0x63);
    working[3] = byte((state_95_bits & 0x8A) as u32 ^ 0x64);
    let combined_left = local[initial[74] as usize & 0x3F];
    let cubed_bits = cube_byte(state_95_bits | initial[200].wrapping_add(0x80));
    let combined_right =
        local[(0_u32.wrapping_sub(cubed_bits as u32).wrapping_add(0x16) & 0x3F) as usize];
    local[40] = byte(cube_byte((initial[245] & 0x18) ^ 0x63) as u32 + 0xAE);
    state[174] = 0_u32
        .wrapping_sub(fixed[working[initial[92] as usize & 0x3F] as usize & 0x3F] as u32)
        .wrapping_sub(fixed[initial[6] as usize & 0x3F] as u32)
        .wrapping_add(initial[174] as u32) as u8;
    let state_103_lookup = working[initial[59] as usize & 0x3F];
    let majority_bits =
        (majority_right & majority_left) | ((majority_right | majority_left) & state_95_bits);
    let table_bits =
        ((majority_bits & 0x99) | (local[26] & ((majority_bits ^ 0x19) | 0x99))) ^ 0xBE;
    let selected_bits =
        (state_103_lookup & 0x2C) | (table_bits & ((state_103_lookup & 0xD3) ^ 0x2C));
    let shift_source = initial[21] | fixed[state[34] as usize & 0x3F];
    state[103] = initial[103]
        ^ xor_shifts(
            selected_bits as u32,
            (shift_source & 7) as u32,
            0_u32.wrapping_sub(shift_source as u32) & 7,
        );
    working[60] = 0x97_u8.wrapping_add(4);
    let state_23_bits = (initial[45] & 0xF4) | ((fixed[initial[173] as usize & 0x3F] / 3) & 9);
    state[23] = state_23_bits ^ 2;
    let shifted_lookup = xor_shifts(
        fixed[((0xFD ^ 0x7F) + 0xC6) & 0x3F] as u32,
        0_u32.wrapping_sub(initial[120] as u32) & 7,
        (initial[120] & 7) as u32,
    );
    let scaled_bits = byte(((3 * rotated_bits as u32) & 0x3D) + rotated_bits as u32);
    state[235] = byte(
        initial[235] as u32
            ^ ((shifted_lookup & scaled_bits) as u32
                | ((shifted_lookup | scaled_bits) as u32 & 0xDE)),
    );
    working[15] = working[15].wrapping_add(0x32);
    working[53] = byte(
        0x13_u32
            ^ ((((0xE1 & 0xBC) ^ 0xBC) & (working[38] ^ 0xFF)) as u32
                | (0_u32.wrapping_sub(cubed_bits as u32).wrapping_add(0x96) & working[38] as u32)),
    );
    state[126] = byte(
        initial[126] as u32 ^ (local[initial[74] as usize & 0x3F].wrapping_add(0x3B) as u32 * 3),
    );
    state[224] = 0xEE;
    state[253] = initial[146];
    let table_36_left = local[state[235] as usize & 0x3F];
    let table_36_right = working[initial[111] as usize & 0x3F];
    state[10] = initial[10].wrapping_add(0x7D);
    working[36] = byte(
        ((initial[99] as u32 * 2)
            ^ (((table_36_right ^ 0x5A) & 0xF0) | ((table_36_left ^ 0x7D) & 0x0F)) as u32
            ^ 0xE1)
            ^ 0x5D,
    );
    let output_30_left = working[initial[9] as usize & 0x3F];
    let output_30_right = local[initial[168] as usize & 0x3F];
    let combined_lookups = ((combined_right ^ 1) & (combined_left ^ 1))
        | (0x2C & ((combined_right ^ 1) | (combined_left ^ 1)));
    let lookup_index = byte(
        (combined_lookups as u32 >> 1)
            .wrapping_sub(combined_lookups as u32 & 0x0C)
            .wrapping_add(6),
    );
    working[13] = 0x0A;
    let table_2_mask = local[initial[53] as usize & 0x3F];
    let table_2_bits = fixed[initial[105] as usize & 0x3F] | 0x48;
    working[2] =
        (table_2_bits & (table_2_mask ^ 0xFF)) | ((table_2_bits | (table_2_mask ^ 0xFF)) & 0xE8);
    let product = byte(
        local[initial[22] as usize & 0x3F] as u32 * fixed[initial[165] as usize & 0x3F] as u32,
    );
    working[55] = byte(product as u32 * product as u32);
    let output_7_lookup = fixed[working[initial[62] as usize & 0x3F] as usize & 0x3F];
    state[252] = initial[252] ^ 0x5C;
    working[51] = byte(0xFA_u32.wrapping_add(
        initial[210] as u32
            | local[58].wrapping_add(local[((output_7_lookup / 5) ^ 0x34) as usize]) as u32,
    ));
    state[33] = initial[33].wrapping_sub(byte(
        (working[initial[249] as usize & 0x3F] as u32 * 0xA1) >> 1,
    ));
    local[27] = byte(initial[217] as u32 * initial[217] as u32 + 0xDC);
    state[172] = initial[172] ^ (initial[40] & 0x51) ^ 0xD5;
    working[56] = (initial[106] & (lookup_index ^ 0x18))
        | ((lookup_index ^ 0xA7) & ((initial[22] & 0x24) ^ 0x8B));
    let table_32_lookup = fixed[initial[181] as usize & 0x3F];
    working[32] = byte(0xE8_u32.wrapping_add(
        (((((local[initial[130] as usize & 0x3F] ^ 0x7D) & 0x32)
            | (fixed[initial[213] as usize & 0x3F] & 0xCD))
            ^ 0x30)
            & ((table_32_lookup & local[8]) | (0xBA & (table_32_lookup | local[8]))))
            as u32,
    ));
    let output_18_left = working[initial[165] as usize & 0x3F];
    local[1] = local[initial[35] as usize & 0x3F] ^ 0x3C;
    let output_18_right = local[initial[85] as usize & 0x3F];
    let adjustments: [u8; 32] = [
        lookup_index ^ 0xE7,
        0x46,
        xor_shifts(
            byte(fixed[initial[254] as usize & 0x3F] as u32 * 3) as u32,
            (output_2_shift & 7) as u32,
            0_u32.wrapping_sub(output_2_shift as u32) & 7,
        ),
        0xFA,
        0x0F,
        0x2C,
        0x0C,
        (output_7_lookup / 5) ^ 0x74,
        0x26,
        fixed[initial[136] as usize & 0x3F].wrapping_add(0x25),
        0xBC,
        0x6B,
        0x48,
        state_95_bits,
        0x48,
        0xA1,
        0xD0,
        scaled_bits,
        byte(
            (((output_18_right ^ 0x7D) & 0x5E) as u32
                | (((output_18_left ^ 0x5A) as u32 * 2) & 0xA0))
                ^ 0xFC,
        ),
        0x3A,
        table_bits,
        0x7B,
        0x6B,
        byte(0_u32.wrapping_sub(cubed_bits as u32).wrapping_add(0x96)),
        0xEE,
        0x42,
        0x77,
        initial[105],
        0xFA,
        2,
        ((output_30_left & output_30_right)
            | ((output_30_left ^ 8) | (output_30_right ^ 9)) & 0x76)
            & 0xD6,
        0x67,
    ];
    for (index, delta) in adjustments.iter().enumerate() {
        add_wrapped(output, index, *delta);
    }
    fold_tables(output, &working, &local);
}

fn adjust_seed(state: &mut [u8; STATE_LEN], output: &mut [u8], parameters: &[u8; 128]) {
    assert!(!output.is_empty(), "empty provisioning adjustment output");
    let initial = *state;
    let mut working = unmask_u8(&SEED_WORKING_BASE, SEED_WORKING_BASE_SEED);
    let mut local = [0_u8; 64];
    let mut fixed = [0_u8; 64];
    for index in 0..local.len() {
        local[index] = parameters[64 + index] ^ 0x78;
        fixed[index] = parameters[index].wrapping_add(0xE9);
    }
    let table_26_lookup = fixed[initial[90] as usize & 0x3F];
    let product_26 = initial[75] as u32 * table_26_lookup as u32;
    working[26] = byte(
        ((product_26 >> 1) as u8 as u32)
            .wrapping_sub(product_26 & 0xF2)
            .wrapping_add(0x79)
            ^ 0x79,
    );
    state[197] = initial[69].wrapping_add(initial[197]);
    working[40] = initial[231] ^ 0xF3;
    state[239] = initial[239].wrapping_add(0xE1);
    let state_bits = (initial[153] & 0x1A) | (initial[194] & 0xE4);
    local[23] = byte(
        (state_bits as u32 >> 1)
            .wrapping_sub(state_bits as u32 & 0xF0)
            .wrapping_add(0x78)
            ^ 0x78,
    );
    local[6] = 0x28;
    let table_5_lookup = working[initial[153] as usize & 0x3F];
    let product_5 = 0xFE_u32 * ((table_5_lookup & 0x18) ^ 0x22) as u32;
    working[5] = byte(
        (0x77_u32
            .wrapping_add(((table_5_lookup & 0x18) ^ 0xDE) as u32)
            .wrapping_sub((2_u32 * 0x77 + product_5) & 0xF2)
            .wrapping_add(0x79))
            ^ 0x79,
    );
    local[5] = byte(2 * (fixed[initial[17] as usize & 0x3F] / 5) as u32);
    let shifted_constant = xor_shifts(
        0x77,
        (initial[230] & 7) as u32,
        0_u32.wrapping_sub(initial[230] as u32) & 7,
    );
    let output_mask = shifted_constant & 0x92;
    working[11] = shifted_constant & 0x10;
    let table_22_lookup = local[initial[51] as usize & 0x3F];
    let table_22_shift = working[initial[112] as usize & 0x3F];
    state[64] = working[initial[103] as usize & 0x3F].wrapping_add(initial[64]);
    state[11] = initial[121] >> 1;
    working[32] = 0x1A_u8.wrapping_add(0x4B) ^ 0x80;
    working[52] = 0xDC ^ (((0x39 & 0xAD) ^ 0x83) / 5);
    let table_45_lookup = working[initial[59] as usize & 0x3F];
    let shifted_lookup = xor_shifts(
        ((table_22_lookup & 0x90) ^ 0x2A) as u32,
        ((table_22_shift & 2) ^ 7) as u32,
        ((table_22_shift & 2) ^ 1) as u32,
    );
    local[22] = shifted_lookup.wrapping_add(0x62);
    working[45] = byte(
        (0xFD_u32
            .wrapping_add(((table_45_lookup ^ 0x79) as u32 >> 1) & 0x1C ^ 0x82)
            .wrapping_sub((2_u32 * 0xFD + ((table_45_lookup & 0x38) ^ 0x3C) as u32) & 0xF2)
            .wrapping_add(0x79))
            ^ 0x79,
    );
    working[53] = 0x5E;
    local[12] = 0x84;
    let output_8_lookup = local[initial[75] as usize & 0x3F];
    let table_2_left = fixed[initial[198] as usize & 0x3F];
    let table_2_right = fixed[initial[163] as usize & 0x3F];
    working[2] = byte(0x7C_u32.wrapping_add(
        ((initial[65] & 0x33)
            | ((table_2_right & table_2_left) & 0xCC)
            | ((table_2_right | table_2_left) & 0xC8)) as u32,
    ));
    state[81] = byte(2 * state[239] as u32 + 0xA4);
    let difference_left = local[initial[130] as usize & 0x3F];
    let difference_right = working[initial[83] as usize & 0x3F];
    working[41] = byte(0xA1 ^ ((state[64] ^ 0xFF) as u32 * (initial[151] ^ 0x2D) as u32));
    let state_192_shift = working[initial[158] as usize & 0x3F];
    state[192] = byte(
        (initial[192] as u32 ^ byte(0x50_u32 << (state_192_shift & 7)) as u32)
            ^ byte(0x50_u32 >> (0_u32.wrapping_sub(state_192_shift as u32) & 7)) as u32,
    );
    let combined_left = working[initial[191] as usize & 0x3F];
    let combined_right = fixed[initial[175] as usize & 0x3F];
    state[76] = (0xC6 & 0xDD) ^ 0x86;
    working[49] = 0x80_u8.wrapping_add(0x43);
    state[131] = initial[131].wrapping_sub((fixed[initial[160] as usize & 0x3F] / 3) & 0x76);
    let state_10_lookup = local[initial[210] as usize & 0x3F];
    state[10] = initial[10]
        .wrapping_sub(!((state_10_lookup & 0x0F) | (0xC5 & ((state_10_lookup & 0xF0) ^ 0x0F))));
    working[22] = byte(0xE6_u32.wrapping_sub(
        (((working[initial[72] as usize & 0x3F] ^ 0xDD) & initial[139]) & 0xA7) as u32,
    ));
    let lookup_difference = difference_right.wrapping_sub(difference_left) | 8;
    let lookup_bias = 0_u32
        .wrapping_sub(lookup_difference as u32)
        .wrapping_sub(13) as u8;
    local[14] = local[initial[48] as usize & 0x3F]
        .wrapping_sub(
            (fixed[lookup_bias as usize & 0x3F] & (working[11] ^ 0xFF)) | (working[11] & 0x94),
        )
        .wrapping_add(0xDA);
    let combined_lookups =
        (combined_left & combined_right) | ((combined_left | combined_right) & 0x7D);
    let folded_bits = combined_lookups.rotate_left(1);
    working[51] = folded_bits ^ 0xC1;
    let output_9_shift = local[initial[146] as usize & 0x3F];
    let square_lookup = working[initial[247] as usize & 0x3F];
    working[32] ^=
        byte(((((0xE1 & 0xE2) ^ 0xE2) | (initial[203] & 0xE1)) as u32).wrapping_add(0xD8));
    let output_21_lookup = local[initial[211] as usize & 0x3F];
    let state_77_left = fixed[initial[180] as usize & 0x3F];
    let state_77_right = fixed[initial[194] as usize & 0x3F];
    let state_77_bits = ((initial[23] ^ 0x40) | state_77_left) & 0xB9;
    state[77] = byte(
        (((initial[23] & state_77_left) | state_77_bits) as u32 & (state_77_right as u32 * 3))
            | (((3 * state_77_right as u32 + 0x80)
                | ((initial[23] & state_77_left) as u32)
                | state_77_bits as u32)
                & 0x75),
    );
    working[57] = lookup_difference.wrapping_add(0x6D).wrapping_add(0x4D);
    local[53] = initial[238];
    local[41] = cube_byte(fixed[lookup_bias as usize & 0x3F].wrapping_add(0x80) & 0x63);
    working[29] = 0x9C_u8.wrapping_sub(initial[207]);
    local[49] =
        !(((initial[115] & 0x75) | (fixed[initial[113] as usize & 0x3F] & 0x8A)) ^ 0x1B) ^ 0x78;
    let table_36_lookup = working[initial[185] as usize & 0x3F];
    let table_36_mask = local[initial[242] as usize & 0x3F];
    working[36] = (fixed[table_36_lookup as usize & 0x3F] ^ 0xC4)
        ^ ((table_36_mask & 0x43) | (0x39 & (table_36_mask | 0x43)));
    #[allow(clippy::identity_op)]
    let folded_constant = (0x1C & 0xC1) ^ 0xC1;
    local[46] = (folded_constant
        | (xor_shifts(
            0xF6,
            0_u32.wrapping_sub(initial[128] as u32) & 7,
            (initial[128] & 7) as u32,
        ) & 0x1C))
        ^ 0x8A;
    local[48] = 0xD4;
    let table_10_lookup = working[initial[166] as usize & 0x3F];
    working[10] = 0x59
        ^ ((0xA7 & (table_10_lookup ^ 0x88))
            | ((!(0xA7 ^ 0x79) | !(table_10_lookup ^ 0x79)) & 0x51));
    let square_input = (square_lookup & (local[6] ^ 0xFF)) | (local[6] & 0x69);
    let squared_lookup = byte(square_input as u32 * square_input as u32);
    let table_34_lookup = working[((squared_lookup & 0x3F) ^ 0x0B) as usize];
    let table_34_mask = working[initial[147] as usize & 0x3F];
    working[34] = byte(0xD5_u32.wrapping_add(table_34_lookup as u32).wrapping_add(
        ((initial[53] & table_34_mask) | ((initial[53] | table_34_mask) & 0x33)) as u32,
    ));
    let state_163_left = local[initial[116] as usize & 0x3F];
    let state_163_right = local[initial[56] as usize & 0x3F];
    let state_163_lookup = working[initial[143] as usize & 0x3F];
    let square_adjustment = squared_lookup ^ 0xCB;
    state[163] = initial[163].wrapping_sub(byte(
        ((state_163_lookup as u32 * 3) & (0xD9_u32 ^ 0xFF))
            | (0xD9_u32
                & (((state_163_right & (square_adjustment ^ 0xFF))
                    | (square_adjustment & state_163_left)) as u32)),
    ));
    local[8] = (0x8C & 0xCB) ^ 0xA7;
    let table_7_lookup = fixed[state[76] as usize & 0x3F];
    working[7] =
        0xA8_u8.wrapping_sub((table_7_lookup & 0x18) | (working[51] & (table_7_lookup | 0x18)));
    working[2] = byte(
        (((byte((((lookup_bias | 0xC3) as u32 * 0xCD) & 0xFC00) >> 10) ^ 0x39) as u32)
            .wrapping_add(0x40))
            ^ 0x79,
    );
    working[23] = 0x15_u8.wrapping_add(5);
    let output_0_lookup = fixed[initial[130] as usize & 0x3F];
    let table_11_left = local[initial[32] as usize & 0x3F];
    let table_11_right = fixed[state[10] as usize & 0x3F];
    working[11] = initial[237]
        & ((table_11_left & table_11_right) | (((table_11_left ^ 0x20) | table_11_right) & 0xDE));
    state[32] = initial[32]
        .wrapping_sub(((initial[111] / 5) & (folded_bits ^ 0x3E)) | (working[51] & 0x19));
    let output_delta = (initial[180] & 0xC3) | 0x10;
    let adjustments: [u8; 32] = [
        byte(
            0_u32
                .wrapping_sub(
                    ((output_0_lookup & 0x88) | 0x17) as u32
                        * ((output_0_lookup & 0x88) | 0x17) as u32,
                )
                .wrapping_add(0xE7),
        ),
        0x78,
        0xDD,
        0x6F,
        0x79,
        0xB2,
        byte(
            0_u32
                .wrapping_sub(lookup_difference as u32)
                .wrapping_add(0xB3),
        ),
        0x88,
        byte(
            (output_mask as u32)
                .wrapping_sub(
                    (((output_8_lookup.wrapping_add(0xCF)) & output_delta)
                        | (((output_8_lookup ^ 0x40).wrapping_add(0x0F)) & 0x2D)
                        | (output_delta & 0x2D)) as u32,
                )
                .wrapping_add(0x1D),
        ),
        xor_shifts(
            fixed[initial[127] as usize & 0x3F] as u32,
            (output_9_shift.wrapping_add(0xB6) & 7) as u32,
            ((output_9_shift ^ 0xFF).wrapping_add(0x53) & 7) as u32,
        ),
        0xA7,
        square_adjustment,
        0x3F,
        0x41,
        0xB9,
        6,
        0xE0,
        0xBB,
        working[51],
        0xB1,
        0x63,
        byte(
            (((output_21_lookup ^ 0x18) | 0x9E) as u32)
                .wrapping_add(fixed[initial[187] as usize & 0x3F] as u32)
                .wrapping_add(0x2A),
        ),
        0xC3,
        0x3B,
        0x7D,
        shifted_lookup.wrapping_add(0x62),
        0xC3,
        0xD3,
        0xA5,
        0x93,
        0x94,
        0xDE,
    ];
    for (index, delta) in adjustments.iter().enumerate() {
        add_wrapped(output, index, *delta);
    }
    fold_tables(output, &working, &local);
}

fn mix_seed(input: &[u8], parameters: &[u8; 128]) -> Vec<u8> {
    assert!(
        (80..=256).contains(&input.len()),
        "provisioning hardware seed must contain 80 to 256 bytes"
    );
    let mut length_sum = 11_u32;
    for index in 0..input.len() + 172 {
        let decoded = input[index % input.len()].wrapping_add(0x92);
        length_sum = (length_sum + 34 * (decoded as u32 % 41)) % 41;
    }
    let mut output = vec![0x87_u8; 20 + length_sum as usize];
    let mut state = [0_u8; STATE_LEN];
    for index in 0..STATE_LEN {
        state[index] = input[index % input.len()].wrapping_add(0x92);
    }
    for index in 0..1536 {
        let first = state[wrapped_index(index, 13, STATE_LEN)];
        let second = state[wrapped_index(index, 57, STATE_LEN)];
        let third = state[wrapped_index(index, 155, STATE_LEN)];
        let value = &mut state[index % STATE_LEN];
        *value = (u32::from(*value) ^ u32::from(first.rotate_left(3)))
            .wrapping_add(u32::from(second.rotate_left(5)))
            .wrapping_sub(u32::from(third.rotate_left(7))) as u8;
    }
    adjust_mixer(&mut state, &mut output, parameters);
    for (index, value) in state.iter().enumerate() {
        let target = index % output.len();
        output[target] ^= *value;
    }
    for index in 0..256 {
        let first = output[wrapped_index(index, 7, output.len())];
        let second = output[wrapped_index(index, 37, output.len())];
        let third = output[wrapped_index(index, 177, output.len())];
        let target = index % output.len();
        output[target] ^= first.rotate_left(1) ^ second.rotate_left(6) ^ third.rotate_left(5);
    }
    output
}

fn make_seed(hardware: &[u8; 20], parameters: &[u8; 128]) -> Vec<u8> {
    let mut length_sum = 43_u32;
    for index in 0..146 {
        length_sum = (length_sum + 14 * (hardware[index % hardware.len()] as u32 % 177)) % 177;
    }
    let mut output = vec![0xE5_u8; 80 + length_sum as usize];
    let mut state = [0_u8; STATE_LEN];
    for index in 0..STATE_LEN {
        state[index] = hardware[index % hardware.len()];
    }
    for index in 0..1536 {
        let first = state[previous_index(index, 13, STATE_LEN)];
        let second = state[previous_index(index, 57, STATE_LEN)];
        let third = state[previous_index(index, 155, STATE_LEN)];
        let value = &mut state[index % STATE_LEN];
        *value = (u32::from(*value) ^ u32::from(first.rotate_left(3)))
            .wrapping_add(u32::from(second.rotate_left(5)))
            .wrapping_sub(u32::from(third.rotate_left(7))) as u8;
    }
    adjust_seed(&mut state, &mut output, parameters);
    for (index, value) in state.iter().enumerate() {
        let target = index % output.len();
        output[target] ^= *value;
    }
    for index in 0..256 {
        let size = output.len();
        let first = output[previous_index(index, 7, size)];
        let second = output[previous_index(index, 37, size)];
        let third = output[previous_index(index, 177, size)];
        let target = index % size;
        output[target] ^= first.rotate_left(1) ^ second.rotate_left(6) ^ third.rotate_left(5);
    }
    for value in output.iter_mut() {
        *value = value.wrapping_sub(0x92);
    }
    output
}

fn hardware_digest(hardware: &[u8; 20], parameters: &[u8; 256]) -> [u8; 20] {
    let seed_parameters: &[u8; 128] = parameters[..128].try_into().unwrap();
    let mix_parameters: &[u8; 128] = parameters[128..].try_into().unwrap();
    let seed = make_seed(hardware, seed_parameters);
    let message = mix_seed(&seed, mix_parameters);
    Sha1::digest(&message).into()
}

pub(super) fn hardware_tag(hardware: &[u8; 20], parameters: &[u8; 272]) -> [u8; 20] {
    let digest_parameters: &[u8; 256] = parameters[..256].try_into().unwrap();
    let mut tag = hardware_digest(hardware, digest_parameters);
    let key: &[u8; 16] = parameters[256..].try_into().unwrap();
    let mut block = [0_u8; 16];
    block.copy_from_slice(&tag[..16]);
    let encrypted = crypto::encrypt_block(&crypto::cipher(key), &block);
    tag[..16].copy_from_slice(&encrypted);
    tag
}
