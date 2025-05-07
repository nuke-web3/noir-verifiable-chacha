use chacha20::chacha20;
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

    let ciphertext = chacha20(key, nonce, counter, plaintext);

    let mut output: [u8; HEADER_LEN + N] = [0; HEADER_LEN + N];
    let mut offset = 0;

    for i in 0..HASH_LEN {
        output[offset + i] = key_hash[i];
    }
    offset += HASH_LEN;

    for i in 0..NONCE_LEN {
        output[offset + i] = nonce[i];
    }
    offset += NONCE_LEN;

    for i in 0..HASH_LEN {
        output[offset + i] = plaintext_hash[i];
    }
    offset += HASH_LEN;

    for i in 0..N {
        output[offset + i] = ciphertext[i];
    }

    output
}
