pub(crate) global KEY_LEN: u32 = 32;
pub(crate) global HASH_LEN: u32 = 32;
pub(crate) global NONCE_LEN: u32 = 12;
// ZkOutput {
//   privkey_hash,
//   nonce,
//   plaintext_hash,
//   ciphertext,
// }
pub(crate) global HEADER_LEN: u32 = HASH_LEN + NONCE_LEN + HASH_LEN;
