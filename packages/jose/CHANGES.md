# Changes

## Version 0.0.1

Unreleased

- Initial release implementing draft-ietf-jose-hpke-encrypt-22.
- JWE Integrated Encryption via `JoseEncrypt0`.
- JWE Key Encryption via `JoseEncrypt`.
- `open()` accepts the Compact, Flattened JSON and General JSON Serializations.
- HPKE-0 through HPKE-7 for Integrated Encryption, and HPKE-0-KE through
  HPKE-7-KE except HPKE-4-KE and HPKE-6-KE for Key Encryption.
- JWK key import support.
- PSK mode support. The `psk_id` header parameter carries `BASE64URL(id)`.
- Built on @hpke/core.
