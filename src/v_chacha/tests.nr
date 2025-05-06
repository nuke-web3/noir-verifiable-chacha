use super::constants::{HEADER_LEN, KEY_LEN, NONCE_LEN};
use super::v_chacha20;
use chacha20::chacha20;

#[export]
fn test_v_chacha20_116_bytes(
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    counter: u32,
    // FIXME: hack to get the compiler happy
    // leng wanted is 4 times what is below
    plaintext: [u8; 116],
) -> [u8; HEADER_LEN + 116] {
    v_chacha20(key, nonce, counter, plaintext)
}

#[test]
fn v_chacha20_8_bytes() {
    let key = [0 as u8; KEY_LEN];
    let nonce = [0 as u8; NONCE_LEN];
    let counter = 0 as u32;
    let plaintext = [0 as u8; 8];

    let output = v_chacha20(key, nonce, counter, plaintext);
    let result = last_bytes::<_,8>(output);
    let expected = chacha20(key, nonce, counter, plaintext);
    assert(result == expected);
}

/// Returns the last M elements from an array of length N.
/// I.E.: last_bytes([1,2,3,4,5], 3) -> [3,4,5]
///
/// ## Example
///
/// last_bytes::<_,3>([0 as u8; 20) -> [0,0,0]
fn last_bytes<let N: u32, let M: u32>(input: [u8; N]) -> [u8; M] {
    assert(M <= N); // optional safety check

    let mut output: [u8; M] = [0; M];
    let start = N - M;

    for i in 0..M {
        output[i] = input[start + i];
    }

    output
}
