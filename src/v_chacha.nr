use chacha20::ChaCha20;
use sha256::sha256_var;

mod tests;
pub mod constants;
use constants::{HASH_LEN, HEADER_LEN, KEY_LEN, NONCE_LEN};

/// Chacha20 verifiable encryption
pub fn v_chacha<let N: u32>(
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    plaintext: [u32; N],
) -> [u8; HEADER_LEN + (N * 4)] {
    let key_bytes = u32_array_to_u8_array(key);
    let key_hash = sha256_var(key_bytes, N as u64);

    let plaintext_bytes = u32_array_to_u8_array(plaintext);
    let plaintext_hash = sha256_var(plaintext_bytes, N as u64);

    let nonce_bytes = u32_array_to_u8_array(nonce);

    let ciphertext = ChaCha20(key, nonce, counter, plaintext);
    let ciphertext_bytes = u32_array_to_u8_array(ciphertext);

    let mut output: [u8; HEADER_LEN + (N * 4)] = [0; HEADER_LEN + (N * 4)];
    let mut offset = 0;

    for i in 0..HASH_LEN {
        output[offset + i] = key_hash[i];
    }
    offset += 32;

    for i in 0..NONCE_LEN {
        output[offset + i] = nonce_bytes[i];
    }
    offset += 12;

    for i in 0..HASH_LEN {
        output[offset + i] = plaintext_hash[i];
    }
    offset += 32;

    for i in 0..(N * 4) {
        output[offset + i] = ciphertext_bytes[i];
    }

    output
}

/// FIXME: this is a wastefull helper... wish we could cast.
fn u32_array_to_u8_array<let N: u32>(input: [u32; N]) -> [u8; N * 4] {
    let mut output: [u8; N * 4] = [0; N * 4];

    for i in 0..N {
        let val = input[i];
        output[i * 4] = (val & 0xFF) as u8;
        output[i * 4 + 1] = ((val >> 8) & 0xFF) as u8;
        output[i * 4 + 2] = ((val >> 16) & 0xFF) as u8;
        output[i * 4 + 3] = ((val >> 24) & 0xFF) as u8;
    }

    output
}
