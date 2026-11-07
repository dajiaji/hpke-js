# Changes

## Unreleased

- Added `generateKemKeyPair()` to `JoseEncrypt0`, matching the Key Encryption
  API and simplifying recipient key generation.

## Version 0.0.1

Released 2026-11-03

- Initial release implementing draft-ietf-jose-hpke-encrypt-22.
- JWE Integrated Encryption via `JoseEncrypt0`.
- JWE Key Encryption via `JoseEncrypt`. Factories accept an `AeadInterface`
  object, e.g. `createJoseHpke3Ke(new Aes256Gcm())`, independently of the HPKE
  suite used for key wrapping. `Aes128Gcm`, `Aes256Gcm` and the `AeadInterface`
  type are re-exported. The JWE `enc` is derived from the supplied AEAD;
  unsupported algorithms or inconsistent AEAD parameters are rejected.
- Key Encryption validates the unwrapped CEK length and clears the CEK after
  encryption and decryption, including on failure (best effort). Encryption and
  content decryption failures are reported as `JoseError`, retaining the
  original error as `cause`.
- `open()` accepts the Compact, Flattened JSON and General JSON Serializations.
- HPKE-0 through HPKE-7 for Integrated Encryption, and HPKE-0-KE through
  HPKE-7-KE except HPKE-4-KE and HPKE-6-KE for Key Encryption.
- JWK key import support.
- PSK mode support. The `psk_id` header parameter carries `BASE64URL(id)`.
- Built on @hpke/core.
