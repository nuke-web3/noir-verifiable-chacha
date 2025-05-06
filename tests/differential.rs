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
fn test_prop_v_chacha_4_bytes() {
    // FIXME: relative path seems to fail, using deps.
    // Upstream bug?
    let runner = NoirRunner::try_new(PathBuf::from("/home/nuke/git/noir/verifiable-chacha")).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let key = [0u8; KEY_LEN];
    let nonce = [0u8; NONCE_LEN];
    let counter = 0u32;

    let strategy = prop::array::uniform::<_, 1>(0..u32::MAX);

    test_runner
        .run(&strategy, |vector| {
            let input = BTreeMap::from([
                ("key".to_string(), [0; KEY_LEN / 4].to_noir()),
                ("nonce".to_string(), [0; NONCE_LEN / 4].len().to_noir()),
                ("counter".to_string(), 0u32.to_noir()),
                ("plaintext".to_string(), vector.len().to_noir()),
            ]);

            let result = runner.run("test_v_chacha_8_bytes", input).unwrap().unwrap();

            let key_hash: [u8; HASH_LEN] = Sha256::digest(&key).into();
            let plaintext_bytes: &[u8; 4] = unsafe { std::mem::transmute(&vector) };
            let plaintext_hash: [u8; HASH_LEN] = Sha256::digest(&plaintext_bytes).into();

            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
            let mut ciphertext = plaintext_bytes.clone();
            cipher.apply_keystream(&mut ciphertext);

            let expected = [
                &key_hash[..],
                &nonce[..],
                &plaintext_hash[..],
                &ciphertext[..],
            ]
            .concat();
            assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}
