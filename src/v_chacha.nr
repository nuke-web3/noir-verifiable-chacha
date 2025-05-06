use chacha20::ChaCha20;
use sha256::sha256_var;

mod tests;
pub mod constants;
use constants::{HASH_LEN, HEADER_LEN, KEY_LEN, NONCE_LEN};

/// ChaCha20 verifiable encryption
pub fn v_chacha20<let N: u32>(
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    counter: u32,
    plaintext: [u8; N],
) -> [u8; HEADER_LEN + N] {
    let key_hash = sha256_var(key, KEY_LEN as u64);

    let plaintext_hash = sha256_var(plaintext, N as u64);

    let ciphertext = ChaCha20(key, nonce, counter, plaintext);

    let mut output: [u8; HEADER_LEN + N] = [0; HEADER_LEN + N];
    let mut offset = 0;

    for i in 0..HASH_LEN {
        output[offset + i] = key_hash[i];
    }
    offset += 32;

    for i in 0..NONCE_LEN {
        output[offset + i] = nonce[i];
    }
    offset += 12;

    for i in 0..HASH_LEN {
        output[offset + i] = plaintext_hash[i];
    }
    offset += 32;

    for i in 0..N {
        output[offset + i] = ciphertext[i];
    }

    output
}

/// FIXME: this is a wastefull helper... wish we could cast.
fn u32_array_to_little_endian_u8_array<let N: u32>(input: [u32; N]) -> [u8; N * 4] {
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

pub fn u8_array_to_u32_array<let N: u32>(input: [u8; N]) -> [u32; N / 4] {
    let mut output: [u32; N / 4] = [0; N / 4];

    for i in 0..(N / 4) {
        output[i] = (input[i * 4] as u32)
            | ((input[i * 4 + 1] as u32) << 8)
            | ((input[i * 4 + 2] as u32) << 16)
            | ((input[i * 4 + 3] as u32) << 24);
    }

    output
}
