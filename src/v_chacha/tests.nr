use super::constants::HEADER_LEN;
use super::v_chacha;

#[export]
fn test_v_chacha_8_bytes(
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    plaintext: [u32; 1],
) -> [u8; HEADER_LEN + 4] {
    v_chacha(key, nonce, counter, plaintext)
}
