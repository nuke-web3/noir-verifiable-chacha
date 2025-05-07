use super::constants::{HEADER_LEN, KEY_LEN, NONCE_LEN};
use super::v_chacha20;

global RFC_PLAINTEXT_LEN: u32 = 114;

#[export]
fn test_v_chacha20_matches_rfc(
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    counter: u32,
    // FIXME: hack to get the compiler happy
    // leng wanted is 4 times what is below
    plaintext: [u8; RFC_PLAINTEXT_LEN],
) -> [u8; HEADER_LEN + RFC_PLAINTEXT_LEN] {
    v_chacha20(key, nonce, counter, plaintext)
}

#[test]
fn v_chacha20_8_bytes() {
    let key = [0 as u8; KEY_LEN];
    let nonce = [0 as u8; NONCE_LEN];
    let counter = 0 as u32;
    let plaintext = [0 as u8; 8];

    // TODO
    let output = v_chacha20(key, nonce, counter, plaintext);
}
