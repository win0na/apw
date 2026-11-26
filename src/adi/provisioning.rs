//! Native ADI provisioning: SPIM challenge to CPIM request to PTM profile.
//!
//! The flow mirrors the MIT-licensed apple-auth reference: the server's SPIM
//! challenge is authenticated, the selector and start body are built from the
//! caller's entropy, the CPIM response is sealed with the challenge's response
//! key, and the final PTM packet is authenticated and decrypted into a
//! GrandSlam profile.

mod hardware;
mod params;

use sha1::{Digest as _, Sha1};
use sha2::Sha256;

use super::{crypto, Error, Platform, Profile, Result};

/// Packet marker at the end of a version-4 provisioning packet.
const PACKET_MARKER: u32 = 0xED92_81D8;

/// Caller-supplied randomness. All bytes must be nonzero in production.
#[derive(Clone)]
pub struct Entropy {
    pub selector: [u8; 32],
    pub body: [u8; 84],
    pub nonce: [u8; 16],
}

impl Entropy {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut entropy = Self {
            selector: [0; 32],
            body: [0; 84],
            nonce: [0; 16],
        };
        rng.fill_bytes(&mut entropy.selector);
        rng.fill_bytes(&mut entropy.body);
        rng.fill_bytes(&mut entropy.nonce);
        for value in entropy
            .selector
            .iter_mut()
            .chain(entropy.body.iter_mut())
            .chain(entropy.nonce.iter_mut())
        {
            while *value == 0 {
                rng.fill_bytes(std::slice::from_mut(value));
            }
        }
        entropy
    }
}

/// A provisioning session between `midStartProvisioning` and
/// `midFinishProvisioning`.
pub struct Provisioning {
    challenge: [u8; 347],
    body: [u8; 160],
    packet: [u8; 276],
    finished: bool,
}

struct BodyEntropy {
    session_random: [u8; 32],
    first_nonce: [u8; 20],
    second_nonce: [u8; 20],
    padding: [u8; 12],
}

impl BodyEntropy {
    fn from_bytes(body: &[u8; 84]) -> Self {
        Self {
            session_random: body[..32].try_into().unwrap(),
            first_nonce: body[32..52].try_into().unwrap(),
            second_nonce: body[52..72].try_into().unwrap(),
            padding: body[72..].try_into().unwrap(),
        }
    }
}

impl Provisioning {
    pub fn new(
        challenge: &[u8],
        hardware: &[u8; 20],
        unix_seconds: u32,
        platform: Platform,
        entropy: Entropy,
    ) -> Result<Self> {
        let challenge: [u8; 347] = challenge
            .try_into()
            .map_err(|_| Error::Invalid("SPIM challenge framing or authentication is invalid"))?;
        let request = params::request();
        // The start request authenticates the challenge with the end-packet key,
        // which is the reference's `parameters::end().authentication_key`.
        verify_challenge(&challenge, &params::end().authentication_key)?;
        let selector = take_selector_entropy(&entropy.selector)?;
        let source = params::selector_source();
        let selector_input = make_selector_input(&selector, &source, &request.selector.input_mask);
        let body_entropy = BodyEntropy::from_bytes(&entropy.body);
        let body = make_start_body(
            &selector_input,
            hardware,
            &body_entropy,
            -2,
            unix_seconds,
            request,
            platform.id(),
        );
        let packet = make_cpim(&challenge, &body, &entropy.nonce, &request.response)?;
        Ok(Self {
            challenge,
            body,
            packet,
            finished: false,
        })
    }

    pub fn request(&self) -> &[u8] {
        &self.packet
    }

    pub fn finish(&mut self, ptm: &[u8], trust_key: &[u8; 16]) -> Result<Profile> {
        if self.finished {
            return Err(Error::Finished);
        }
        let end = params::end();
        verify_challenge(&self.challenge, &end.authentication_key)?;
        let spim: &[u8; 240] = self.challenge[8..248].try_into().unwrap();
        let payload = decrypt_end_packet(spim, ptm, trust_key, end)?;
        let profile = make_provisioned_profile(&self.body, &payload)?;
        self.finished = true;
        Ok(profile)
    }
}

// --- Challenge and end-packet authentication ------------------------------

fn word(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn integer(bytes: &[u8]) -> u64 {
    let mut value = 0_u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    value
}

/// Encrypt the first 16 bytes of a SHA-1 digest, leaving its last 4 bytes.
fn transform_digest(digest: &mut [u8; 20], key: &[u8; 16]) {
    let mut block = [0_u8; 16];
    block.copy_from_slice(&digest[..16]);
    let encrypted = crypto::encrypt_block(&crypto::cipher(key), &block);
    digest[..16].copy_from_slice(&encrypted);
}

fn verify_challenge(spim: &[u8], key: &[u8; 16]) -> Result<()> {
    const INVALID: Error = Error::Invalid("SPIM challenge framing or authentication is invalid");
    if spim.len() != 347
        || word(&spim[0..4]) != 4
        || word(&spim[4..8]) != 240
        || word(&spim[264..268]) != 52
        || word(&spim[268..272]) != 4
        || word(&spim[320..324]) != PACKET_MARKER
    {
        return Err(INVALID);
    }
    let mut digest: [u8; 20] = Sha1::digest(&spim[4..324]).into();
    transform_digest(&mut digest, key);
    let mut difference = 0_u8;
    for (expected, actual) in digest.iter().zip(&spim[324..344]) {
        difference |= expected ^ actual;
    }
    if difference != 0 {
        return Err(INVALID);
    }
    Ok(())
}

fn has_packet_format(packet: &[u8]) -> bool {
    if !matches!(packet.len(), 311 | 375 | 487 | 503) {
        return false;
    }
    let size = packet.len();
    word(&packet[0..4]) == 4
        && word(&packet[20..24]) as usize == size - 55
        && word(&packet[size - 31..size - 27]) == PACKET_MARKER
}

fn packet_tag(packet: &[u8], key: &[u8; 16]) -> Result<[u8; 20]> {
    if !matches!(packet.len(), 311 | 375 | 487 | 503) {
        return Err(Error::Invalid("unsupported PTM version-4 packet length"));
    }
    let size = packet.len();
    let mut digest: [u8; 20] = Sha1::digest(&packet[4..size - 27]).into();
    transform_digest(&mut digest, key);
    Ok(digest)
}

fn decrypt_end_packet(
    spim_ciphertext: &[u8; 240],
    packet: &[u8],
    trust_key: &[u8; 16],
    parameters: &params::EndParameters,
) -> Result<Vec<u8>> {
    if !has_packet_format(packet) {
        return Err(Error::Invalid(
            "PTM packet framing or authentication is invalid",
        ));
    }
    let size = packet.len();
    let expected = packet_tag(packet, &parameters.authentication_key)?;
    let mut difference = 0_u8;
    for (index, expected) in expected.iter().enumerate() {
        difference |= expected ^ packet[size - 27 + index];
    }
    if difference != 0 {
        return Err(Error::Invalid(
            "PTM packet framing or authentication is invalid",
        ));
    }
    let key = end_payload_key(spim_ciphertext, trust_key, &parameters.payload)?;
    let cipher = crypto::cipher(&key);
    let mut previous: [u8; 16] = packet[4..20].try_into().unwrap();
    let mut plaintext = vec![0_u8; size - 55];
    for offset in (0..plaintext.len()).step_by(16) {
        let mut block = [0_u8; 16];
        block.copy_from_slice(&packet[24 + offset..24 + offset + 16]);
        let decoded = crypto::decrypt_block(&cipher, &block);
        for index in 0..16 {
            plaintext[offset + index] = decoded[index] ^ previous[index];
        }
        previous = block;
    }
    Ok(plaintext)
}

// --- Response-key recovery ------------------------------------------------

fn sbox(value: u8) -> u8 {
    fn multiply(mut left: u8, mut right: u8) -> u8 {
        let mut result = 0_u8;
        while right != 0 {
            if right & 1 != 0 {
                result ^= left;
            }
            let high = left & 0x80 != 0;
            left <<= 1;
            if high {
                left ^= 0x1B;
            }
            right >>= 1;
        }
        result
    }
    let inverse = if value == 0 {
        0
    } else {
        let mut inverse = 1_u8;
        let mut power = value;
        let mut exponent = 254_u32;
        while exponent != 0 {
            if exponent & 1 != 0 {
                inverse = multiply(inverse, power);
            }
            power = multiply(power, power);
            exponent >>= 1;
        }
        inverse
    };
    let mut result = inverse ^ 0x63;
    for rotation in 1..5 {
        result ^= inverse.rotate_left(rotation);
    }
    result
}

fn expand_schedule(key: [u8; 16]) -> [[u8; 16]; 11] {
    const ROUND_CONSTANTS: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
    let mut schedule = [[0_u8; 16]; 11];
    schedule[0] = key;
    for round in 1..schedule.len() {
        let previous = schedule[round - 1];
        let transformed = [
            sbox(previous[13]) ^ ROUND_CONSTANTS[round - 1],
            sbox(previous[14]),
            sbox(previous[15]),
            sbox(previous[12]),
        ];
        for byte in 0..4 {
            schedule[round][byte] = previous[byte] ^ transformed[byte];
        }
        for block in 1..4 {
            for byte in 0..4 {
                let index = block * 4 + byte;
                schedule[round][index] = previous[index] ^ schedule[round][index - 4];
            }
        }
    }
    schedule
}

fn invert_byte_map(map: &[u8; 8]) -> Result<[u8; 8]> {
    let mut rows = [0_u16; 8];
    for (row, value) in rows.iter_mut().enumerate() {
        *value = 1 << (8 + row);
        for (column, basis) in map.iter().enumerate() {
            if basis & (1 << row) != 0 {
                *value |= 1 << column;
            }
        }
    }
    for column in 0..rows.len() {
        let mut pivot = column;
        while pivot < rows.len() && rows[pivot] & (1 << column) == 0 {
            pivot += 1;
        }
        if pivot == rows.len() {
            return Err(Error::Invalid("SPIM response input matrix is singular"));
        }
        rows.swap(column, pivot);
        for row in 0..rows.len() {
            if row != column && rows[row] & (1 << column) != 0 {
                rows[row] ^= rows[column];
            }
        }
    }
    let mut inverse = [0_u8; 8];
    for (column, item) in inverse.iter_mut().enumerate() {
        for (row, value) in rows.iter().enumerate() {
            if value & (1 << (8 + column)) != 0 {
                *item |= 1_u8 << row;
            }
        }
    }
    Ok(inverse)
}

fn response_matrices(encoded: &[u8; 64], parameters: &params::ResponseKey) -> Result<[[u8; 8]; 4]> {
    let mut result = [[0_u8; 8]; 4];
    for (matrix, codec) in parameters.input_matrix_codecs.iter().enumerate() {
        let mut basis = codec.basis_offset;
        for column in &codec.columns {
            let image = crypto::apply_linear_map(&column.column_map, encoded[column.source_byte]);
            for (bit, value) in basis.iter_mut().enumerate() {
                if column.row_mask & (1 << bit) != 0 {
                    *value ^= image;
                }
            }
        }
        result[matrix] = basis;
    }
    Ok(result)
}

fn decode_response_keys(
    material: &[u8; 240],
    parameters: &params::ResponseKey,
) -> Result<[[u8; 16]; 11]> {
    let encoded: &[u8; 64] = material[176..].try_into().unwrap();
    let matrices = response_matrices(encoded, parameters)?;
    let mut inverse = [[0_u8; 8]; 4];
    for (index, matrix) in matrices.iter().enumerate() {
        inverse[index] = invert_byte_map(matrix)?;
    }
    let mut schedule = [[0_u8; 16]; 11];
    for position in 0..parameters.round_key_masks.len() {
        let row = position % 4;
        let encoded =
            crypto::apply_linear_map(&parameters.encoded_key_maps[row], material[position])
                ^ parameters.round_key_masks[position];
        let inverted = crypto::apply_linear_map(&inverse[row], encoded);
        schedule[position / 16][position % 16] =
            crypto::apply_linear_map(&parameters.decoded_key_maps[row], inverted);
    }
    if schedule != expand_schedule(schedule[0]) {
        return Err(Error::Invalid(
            "SPIM response round keys do not form an AES-128 schedule",
        ));
    }
    Ok(schedule)
}

fn decode_response_key(material: &[u8; 240], parameters: &params::ResponseKey) -> Result<[u8; 16]> {
    Ok(decode_response_keys(material, parameters)?[0])
}

fn decode_spim_material(ciphertext: &[u8; 240], parameters: &params::SpimCipher) -> [u8; 240] {
    let cipher = crypto::cipher(&parameters.key);
    let mut previous = parameters.iv;
    let mut output = [0_u8; 240];
    for offset in (0..output.len()).step_by(16) {
        let mut block = [0_u8; 16];
        block.copy_from_slice(&ciphertext[offset..offset + 16]);
        let decrypted = crypto::decrypt_block(&cipher, &block);
        for index in 0..16 {
            output[offset + index] = decrypted[index] ^ previous[index];
        }
        previous = block;
    }
    output
}

fn end_payload_key(
    spim_ciphertext: &[u8; 240],
    trust_key: &[u8; 16],
    parameters: &params::EndPayloadParameters,
) -> Result<[u8; 16]> {
    let material = decode_spim_material(spim_ciphertext, &parameters.spim);
    let response_key = decode_response_key(&material, &parameters.response_key)?;
    let intermediate = crypto::encrypt_block(&crypto::cipher(&response_key), trust_key);
    Ok(crypto::encrypt_block(
        &crypto::cipher(&parameters.key_derivation_key),
        &intermediate,
    ))
}

// --- Start request --------------------------------------------------------

fn take_selector_entropy(random: &[u8]) -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    let mut accepted = 0;
    for value in random {
        if *value != 0 {
            bytes[accepted] = *value;
            accepted += 1;
            if accepted == bytes.len() {
                return Ok(bytes);
            }
        }
    }
    Err(Error::Invalid(
        "provisioning selector needs 32 nonzero random bytes",
    ))
}

fn encrypt_input(input: &[u8; 32], key: &[u8; 16], iv: &[u8; 16], mask: &[u8; 16]) -> [u8; 32] {
    let cipher = crypto::cipher(key);
    let mut previous = *iv;
    let mut output = [0_u8; 32];
    for offset in (0..output.len()).step_by(16) {
        let mut block = [0_u8; 16];
        for index in 0..16 {
            block[index] = input[offset + index] ^ mask[index] ^ previous[index];
        }
        previous = crypto::encrypt_block(&cipher, &block);
        output[offset..offset + 16].copy_from_slice(&previous);
    }
    output
}

fn make_selector_input(
    random: &[u8; 32],
    source: &params::SelectorSource,
    input_mask: &[u8; 16],
) -> [u8; 32] {
    let mut output = encrypt_input(random, &source.key, &source.iv, &[0_u8; 16]);
    for (index, value) in output.iter_mut().enumerate() {
        *value ^= input_mask[index % input_mask.len()];
    }
    output
}

fn write_word(body: &mut [u8; 160], offset: usize, value: u32) {
    body[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn make_body(
    encrypted_material: &[u8; 32],
    device_tag: &[u8; 20],
    entropy: &BodyEntropy,
    dsid: i64,
    unix_seconds: u32,
    platform: u32,
) -> [u8; 160] {
    let mut body = [0_u8; 160];
    write_word(&mut body, 0, 32);
    body[4..36].copy_from_slice(encrypted_material);
    write_word(&mut body, 36, 32);
    body[40..72].copy_from_slice(&entropy.session_random);
    body[72..92].copy_from_slice(device_tag);
    body[92..112].copy_from_slice(&entropy.first_nonce);
    body[112..132].copy_from_slice(&entropy.second_nonce);
    body[132..140].copy_from_slice(&(dsid as u64).to_be_bytes());
    write_word(&mut body, 140, unix_seconds);
    write_word(&mut body, 144, platform);
    body[148..160].copy_from_slice(&entropy.padding);
    body
}

fn make_start_body(
    selector_input: &[u8; 32],
    hardware: &[u8; 20],
    entropy: &BodyEntropy,
    dsid: i64,
    unix_seconds: u32,
    parameters: &params::RequestParameters,
    platform: u32,
) -> [u8; 160] {
    let encrypted = encrypt_input(
        selector_input,
        &parameters.selector.key,
        &parameters.selector.iv,
        &parameters.selector.input_mask,
    );
    let tag = hardware::hardware_tag(hardware, &parameters.hardware);
    make_body(&encrypted, &tag, entropy, dsid, unix_seconds, platform)
}

struct ChallengeFields<'a> {
    encrypted_material: &'a [u8; 240],
    encrypted_digest_parameter: &'a [u8; 16],
    echoed_server_field: &'a [u8; 60],
}

impl<'a> ChallengeFields<'a> {
    fn parse(spim: &'a [u8]) -> Result<Self> {
        if spim.len() < 324 {
            return Err(Error::Invalid("provisioning challenge is truncated"));
        }
        if word(&spim[0..4]) != 4
            || word(&spim[4..8]) != 240
            || word(&spim[264..268]) != 52
            || word(&spim[268..272]) != 4
        {
            return Err(Error::Invalid(
                "unsupported provisioning challenge field layout",
            ));
        }
        Ok(Self {
            encrypted_material: spim[8..248].try_into().unwrap(),
            encrypted_digest_parameter: spim[248..264].try_into().unwrap(),
            echoed_server_field: spim[264..324].try_into().unwrap(),
        })
    }
}

fn encrypt_response_body(plaintext: &[u8; 160], key: &[u8; 16], nonce: &[u8; 16]) -> [u8; 160] {
    let cipher = crypto::cipher(key);
    let mut previous = *nonce;
    let mut ciphertext = [0_u8; 160];
    for offset in (0..plaintext.len()).step_by(16) {
        let mut block = [0_u8; 16];
        for index in 0..16 {
            block[index] = plaintext[offset + index] ^ previous[index];
        }
        previous = crypto::encrypt_block(&cipher, &block);
        ciphertext[offset..offset + 16].copy_from_slice(&previous);
    }
    ciphertext
}

fn make_response(
    plaintext: &[u8; 160],
    key: &[u8; 16],
    nonce: &[u8; 16],
    parameter: &[u8; 16],
    suffix: &[u8; 24],
) -> [u8; 192] {
    let ciphertext = encrypt_response_body(plaintext, key, nonce);
    let mut message = [0_u8; 200];
    message[..160].copy_from_slice(&ciphertext);
    message[160..176].copy_from_slice(parameter);
    message[176..].copy_from_slice(suffix);
    let mut response = [0_u8; 192];
    response[..160].copy_from_slice(&ciphertext);
    response[160..].copy_from_slice(&Sha256::digest(message));
    response
}

fn make_cpim(
    spim: &[u8],
    body: &[u8; 160],
    nonce: &[u8; 16],
    parameters: &params::StartParameters,
) -> Result<[u8; 276]> {
    let fields = ChallengeFields::parse(spim)?;
    let digest_parameter = crypto::decrypt_block(
        &crypto::cipher(&parameters.digest_key),
        fields.encrypted_digest_parameter,
    );
    let material = decode_spim_material(fields.encrypted_material, &parameters.response.spim);
    let key = decode_response_key(&material, &parameters.response.key)?;
    let response = make_response(
        body,
        &key,
        nonce,
        &digest_parameter,
        &parameters.response.hash_suffix,
    );
    let mut packet = [0_u8; 276];
    packet[3] = 5;
    packet[4..20].copy_from_slice(nonce);
    packet[23] = 160;
    packet[24..216].copy_from_slice(&response);
    packet[216..].copy_from_slice(fields.echoed_server_field);
    Ok(packet)
}

// --- Finish ---------------------------------------------------------------

fn make_provisioned_profile(start_body: &[u8; 160], payload: &[u8]) -> Result<Profile> {
    let platform = word(&start_body[144..148]);
    let secondary_size = match platform {
        1 => 400,
        4 => 384,
        _ => 208,
    };
    if !matches!(platform, 1 | 2 | 4)
        || payload.len() != secondary_size + 48
        || word(&start_body[0..4]) != 32
        || word(&start_body[36..40]) != 32
        || integer(&start_body[132..140]) != u64::MAX - 1
        || word(&payload[0..4]) != secondary_size as u32
        || word(&payload[secondary_size + 4..secondary_size + 8]) != 32
    {
        return Err(Error::Invalid("unsupported fresh GrandSlam profile fields"));
    }
    let mut difference = 0_u8;
    for index in 0..32 {
        difference |= start_body[40 + index] ^ payload[secondary_size + 8 + index];
    }
    if difference != 0 {
        return Err(Error::Invalid(
            "provisioning response belongs to a different start session",
        ));
    }
    let platform = match platform {
        1 => Platform::Mac,
        2 => Platform::Windows,
        _ => return Err(Error::Invalid("unsupported ADI provisioning platform")),
    };
    let machine_id: [u8; 60] = start_body[72..132].try_into().unwrap();
    let encrypted_seed: [u8; 32] = start_body[4..36].try_into().unwrap();
    let secondary = payload[4..4 + secondary_size].to_vec();
    Profile::from_parts(
        machine_id,
        secondary,
        encrypted_seed,
        [0_u8; 8],
        None,
        platform,
    )
}
