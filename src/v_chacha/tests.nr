use super::constants::{HEADER_LEN, KEY_LEN, NONCE_LEN};
use super::v_chacha20;

global RFC_PLAINTEXT_LEN: u32 = 114;

#[export]
fn test_v_chacha20_matches_rfc(
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    counter: u32,
    plaintext: [u8; RFC_PLAINTEXT_LEN],
) -> [u8; HEADER_LEN + RFC_PLAINTEXT_LEN] {
    v_chacha20(key, nonce, counter, plaintext)
}

#[export]
fn test_v_chacha20_8_bytes(
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    counter: u32,
    plaintext: [u8; 8],
) -> [u8; HEADER_LEN + 8] {
    v_chacha20(key, nonce, counter, plaintext)
}
