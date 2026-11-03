# Changes

## Unreleased

- **Breaking:** Renamed the factory functions `createHpkeN()` /
  `createHpkeNKe()` to `createCoseHpkeN()` / `createCoseHpkeNKe()` so they do
  not collide with the `@hpke/jose` factories (now `createJoseHpkeN()` /
  `createJoseHpkeNKe()`).
- **Breaking:** The Key Encryption factories take the Layer 0 content encryption
  AEAD as an `AeadInterface` object instead of a `ContentAlg` value, e.g.
  `createCoseHpke3Ke(new Aes128Gcm())`. `Aes128Gcm`, `Aes256Gcm` and
  `Chacha20Poly1305` are re-exported for convenience, and an AEAD without a COSE
  content encryption algorithm (such as Export-Only) is rejected with a
  `CoseError`.
- **Breaking:** Removed the `ContentCrypto` type export.
- Fixed Key Encryption with ChaCha20/Poly1305 content encryption on the AES-GCM
  based suites (HPKE-0/1/2/3/5/7-KE): the content was encrypted with AES-GCM
  while being labelled as ChaCha20/Poly1305 (COSE alg 24).
- `open()` now validates CBOR tags: a message may be untagged or carry its own
  COSE tag (16 for COSE_Encrypt0, 96 for COSE_Encrypt). Any other tag, or a
  tagged value in a header parameter this library uses (such as `ek` or IV), is
  rejected instead of being silently stripped.
- `open()` rejects messages whose protected and unprotected headers share a
  label (RFC 9052 Section 3); COSE_Encrypt recipients with such a label are
  skipped.
- Recipient `kid` matching in `open()` also looks at the recipient unprotected
  header, with the protected header taking precedence.
- All errors are now reported as `CoseError`. Failures from HPKE, the AEAD,
  WebCrypto and COSE_Key import are wrapped with the original error available as
  `cause`.
- The CBOR decoder checks that integer arguments, byte/text strings, arrays and
  maps fit in the remaining input before reading them, so truncated or oversized
  length fields fail early with `CBOR: unexpected end of input`.
- The content encryption key (CEK) is zeroized after `seal()` and `open()`,
  including when they fail.
- The npm ESM build is marked `"sideEffects": false` to improve tree shaking.

## Version 0.0.1

Released 2026-11-03

- Initial release implementing draft-ietf-cose-hpke-27.
- COSE_Encrypt0 (Integrated Encryption) via `CoseEncrypt0`.
- COSE_Encrypt (Key Encryption) via `CoseEncrypt`.
- Minimal CBOR encoder/decoder for COSE structures.
