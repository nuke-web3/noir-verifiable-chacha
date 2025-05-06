# Verifiable ChaCha20

This package contains a verifiable encryption extension to the canonical ChaCha20 stream cypher by committing to the:

- nonce
- privkey hash (SHA2_256)
- plaintext hash (SHA2_256)
- ciphertext bytes

Verifying the proof then and matching the committed metadata for the ciphertext proves that the ciphertext is:

- Correct, no [MAC](https://en.wikipedia.org/wiki/Message_authentication_code) needed (as overall ZKP constrains it)
- "Anchored" to the plaintext via it's hash

**This enables the public to know that some ciphertext is decrypt-able to some important data without decryption.**

## Noir Version Compatibility

This library is tested to work as of Noir v1.0.0-beta.3

## Tests

Property testing is minimally implemented, run with:

```bash
./scripts/fuzz-test.sh
```

## Acknowledgments

Based heavily on the [Noir SHA2 lib](https://github.com/noir-lang/sha256/)
