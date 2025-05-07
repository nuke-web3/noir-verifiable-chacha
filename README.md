# Noir Verifiable ChaCha20

**Enables the public to know that some ciphertext is decrypt-able with a specific privkey to some hidden plaintext without knowing the privkey.**

This package produces a [Noir proof](https://noir-lang.org/docs/) of [ChaCha20 encryption](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) by committing (in byte order) to the:

- privkey hash (SHA2_256),
  - If static, can act as UID to match on.
- nonce,
  - MUST never be reused, else attacks to extract privkey are possible!
- plaintext hash (SHA2_256),
- ciphertext

Verifying the proof then and matching the committed metadata for the ciphertext proves that the ciphertext is:

- Committed to a (public) privkey hash
- Correctly constructed ChaCha20 ciphertext from privkey & nonce - no [MAC](https://en.wikipedia.org/wiki/Message_authentication_code) needed (as overall ZKP constrains it)
- "Anchored" to the plaintext via it's hash

## Noir Version Compatibility

This library is tested to work as of Noir v1.0.0-beta.3

## Tests

We ensure identical behavior for `RustCrypto`'s impl of [SHA2_256](https://github.com/RustCrypto/hashes/tree/master/sha2) and [ChaCha20](https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20).

Run test with:

```bash
./scripts/test-all.sh
```

## Acknowledgments

Based heavily on the [Noir SHA2 lib](https://github.com/noir-lang/sha256/)
