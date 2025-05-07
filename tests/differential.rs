use std::collections::BTreeMap;
use std::path::PathBuf;

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use core::fmt;
use noir_runner::{NoirRunner, ToNoir};
use proptest::{prelude::prop, test_runner::TestRunner};
use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

pub const KEY_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const HEADER_LEN: usize = HASH_LEN + NONCE_LEN + HASH_LEN;

pub struct ZkOutput<'a> {
    pub privkey_hash: [u8; HASH_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub plaintext_hash: [u8; HASH_LEN],
    pub ciphertext: &'a [u8],
}

impl<'a> ZkOutput<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < HEADER_LEN {
            return Err("Input too short for header");
        }

        let (header, ciphertext) = data.split_at(HEADER_LEN);

        let mut privkey_hash = [0u8; HASH_LEN];
        privkey_hash.copy_from_slice(&header[..HASH_LEN]);

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&header[HASH_LEN..HASH_LEN + NONCE_LEN]);

        let mut plaintext_hash = [0u8; HASH_LEN];
        plaintext_hash.copy_from_slice(&header[HASH_LEN + NONCE_LEN..HEADER_LEN]);

        Ok(ZkOutput {
            privkey_hash,
            nonce,
            plaintext_hash,
            ciphertext,
        })
    }
}

impl core::fmt::Debug for ZkOutput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let privkey_hash_hex = bytes_to_hex(&self.privkey_hash);
        let nonce_hex = bytes_to_hex(&self.nonce);
        let plaintext_hash_hex = bytes_to_hex(&self.plaintext_hash);

        let mut hasher = Sha256::new();
        hasher.update(self.ciphertext);
        let ciphertext_hash = hasher.finalize();
        let ciphertext_hash_hex = bytes_to_hex(&ciphertext_hash);

        f.debug_struct("ZkvmOutput")
            .field("privkey_hash", &privkey_hash_hex)
            .field("nonce", &nonce_hex)
            .field("plaintext_hash", &plaintext_hash_hex)
            .field("ciphertext_sha256", &ciphertext_hash_hex)
            .finish()
    }
}

// Helper to get a OsRng nonce of correct length
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.try_fill_bytes(&mut nonce).expect("Rng->buffer");
    nonce
}

// Helper to format bytes as hex for pretty printing
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let digest_hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    digest_hex
}

#[test]
fn test_prop_v_chacha_8_bytes() {
    // FIXME: relative path seems to fail, using deps.
    // Upstream bug?
    let runner =
        NoirRunner::try_new(PathBuf::from("/home/nuke/git/noir/verifiable-chacha")).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    // IMPORTANT: We could test rust `cipher.seek()` behavior by changing the counter,
    // but note that seek is byte-wise and counter is 64 byte block-wise
    let counter = 0u32; // We could test rust `cipher.seek()` behavior, but choose not to here
    let key_strategy = prop::array::uniform::<_, KEY_LEN>(0..=u8::MAX);
    let nonce_strategy = prop::array::uniform::<_, NONCE_LEN>(0..=u8::MAX);
    let plaintext_strategy = prop::array::uniform::<_, 8>(0..=u8::MAX);

    let combined_strategy = (key_strategy, nonce_strategy, plaintext_strategy);

    test_runner
        .run(&combined_strategy, |(key, nonce, plaintext)| {
            let input = BTreeMap::from([
                ("key".to_string(), key.to_noir()),
                ("nonce".to_string(), nonce.to_noir()),
                ("counter".to_string(), counter.to_noir()),
                ("plaintext".to_string(), plaintext.to_noir()),
            ]);

            let result = runner
                .run("test_v_chacha20_8_bytes", input)
                .unwrap()
                .unwrap();

            let key_hash: [u8; HASH_LEN] = Sha256::digest(&key).into();
            let plaintext_bytes = &plaintext;
            let plaintext_hash: [u8; HASH_LEN] = Sha256::digest(&plaintext_bytes).into();

            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
            let mut ciphertext = plaintext_bytes.clone();
            cipher.apply_keystream(&mut ciphertext);

            let expected = [
                &key_hash[..],
                &nonce[..],
                &plaintext_hash[..],
                &ciphertext[..plaintext_bytes.len()],
            ]
            .concat();
            assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}

#[test]
#[allow(non_snake_case)]
/// Inputs from https://datatracker.ietf.org/doc/html/rfc7539#section-2.4.2
fn matches_rustcrypto_chacha20_for_RFC_inputs() {
    // FIXME: relative path seems to fail, using deps.
    // Upstream bug?
    let noir_runner =
        NoirRunner::try_new(PathBuf::from("/home/nuke/git/noir/verifiable-chacha")).unwrap();

    let key: [u8; KEY_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce: [u8; NONCE_LEN] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let counter: u32 = 0x01;
    const RFC_PLAINTEXT_LEN: usize = 114;
    let plaintext: [u8; RFC_PLAINTEXT_LEN] = [
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74,
        0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
        0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20,
        0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
        0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70,
        0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
        0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75,
        0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
    ];
    let expected_ciphertext: [u8; RFC_PLAINTEXT_LEN] = [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69,
        0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f,
        0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd,
        0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
        0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e,
        0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c,
        0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4,
        0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d,
    ];

    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    // NOTE: matches https://github.com/RustCrypto/stream-ciphers/blob/master/chacha20/tests/mod.rs
    // The test vectors omit the first 64-bytes of the keystream
    // We do NOT `seek` to the counter set to 1
    // This emulates it by jumping ahead a block (64 bytes)
    let mut prefix = [0u8; 64];
    cipher.apply_keystream(&mut prefix);
    let mut ciphertext = plaintext.clone();
    cipher.apply_keystream(&mut ciphertext);

    // RustCrypto double check:
    assert_eq!(ciphertext, expected_ciphertext);

    let noir_input = BTreeMap::from([
        ("key".to_string(), key.to_noir()),
        ("nonce".to_string(), nonce.to_noir()),
        ("counter".to_string(), counter.to_noir()),
        ("plaintext".to_string(), plaintext.to_noir()),
    ]);

    let noir_result = noir_runner
        .run("test_v_chacha20_matches_rfc", noir_input)
        .unwrap()
        .unwrap();

    let key_hash: [u8; HASH_LEN] = Sha256::digest(&key).into();
    let plaintext_hash: [u8; HASH_LEN] = Sha256::digest(&plaintext).into();

    let expected = [
        &key_hash[..],
        &nonce[..],
        &plaintext_hash[..],
        &ciphertext[..],
    ]
    .concat();

    assert_eq!(noir_result, expected.to_noir());
}
