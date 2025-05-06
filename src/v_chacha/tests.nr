use super::constants::{HEADER_LEN, KEY_LEN, NONCE_LEN};
use super::v_chacha20;

#[export]
fn test_v_chacha20_8_bytes(
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    counter: u32,
    // FIXME: hack to get the compiler happy
    // leng wanted is 4 times what is below
    plaintext: [u8; 8],
) -> [u8; HEADER_LEN + 8] {
    v_chacha20(key, nonce, counter, plaintext)
}
