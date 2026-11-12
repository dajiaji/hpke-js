# Changes

## Unreleased

- Specialize the internal ChaCha20-Poly1305 implementation for the HPKE AEAD
  interface. `seal()`/`open()` are about 1.3-2x faster on V8 (most for short
  messages) and the minified bundle is about 37% smaller. The public API is
  unchanged.
  - Convert the key to words once per context instead of copying it three times
    per call, and stop copying the nonce, AAD and input data.
  - XOR the keystream directly into the output and process consecutive Poly1305
    blocks without reloading the state.
  - Authenticate and decrypt the same private copy of the ciphertext in
    `open()`, so that a ciphertext in shared memory (`SharedArrayBuffer`) that
    is modified by another thread during the call cannot be decrypted without
    being authenticated.
  - Remove code that is unreachable from the public API: caller-provided output
    buffers, the repeated `encrypt()` guard, the standalone `chacha20` stream
    function and the incremental Poly1305 interface.
  - Error messages for invalid key, nonce and ciphertext lengths have changed
    (`invalid key length`, `invalid nonce length`, `ciphertext too short`).

## Version 1.8.1

Released 2026-11-08

- Reduce ChaCha20-Poly1305 bundle size by simplifying the internal Poly1305
  digest API, specializing cipher validation, and removing redundant Promise
  wrappers. Preserve incremental authentication, output buffers, and input
  validation.
- Reduce bundle size by using the AEAD identifier value directly instead of
  referencing the `AeadId` object.

## Version 1.8.0

Released 2026-03-08

- [(#715) refactor: reuse common noble utilities in chacha20poly1305.](https://github.com/dajiaji/hpke-js/pull/715)
- [(#718) refactor: add test:node prepare steps and use BufferSource in HPKE interfaces.](https://github.com/dajiaji/hpke-js/pull/718)
- [(#724) chore(deps): bump TypeScript to ^5.9.3 in test and sample package.json.](https://github.com/dajiaji/hpke-js/pull/724)
- [(#725) chore: exclude CHANGES.md from JSR publish and add .npmignore to npm packages.](https://github.com/dajiaji/hpke-js/pull/725)

## Version 1.7.1

Released 2025-08-15

- [(#606) chacha20poly1305: remove unused funcs.](https://github.com/dajiaji/hpke-js/pull/606)

## Version 1.7.0

Released 2025-08-09

- [(#547) chacha20poly1305: import chacha20 implementation from @noble/ciphers.](https://github.com/dajiaji/hpke-js/pull/547)

## Version 1.6.3

Released 2025-07-12

- [(#527) base: bump @noble/cipher to 1.3.0](https://github.com/dajiaji/hpke-js/pull/527)
- [(#526) base: bump @hpke/core to 1.7.3](https://github.com/dajiaji/hpke-js/pull/526)
- [(#504) Add deno check to deno.json.](https://github.com/dajiaji/hpke-js/pull/504)

## Version 1.6.2

Released 2025-03-09

- [(#493) Bump @hpke/core to 1.7.2.](https://github.com/dajiaji/hpke-js/pull/493)
- [(#491) Remove package-lock.json for cloudflare test.](https://github.com/dajiaji/hpke-js/pull/491)
- [(#489) Bump @hpke/common to 1.7.2.](https://github.com/dajiaji/hpke-js/pull/489)
- [(#483) Bump @noble/ciphers to 1.2.1.](https://github.com/dajiaji/hpke-js/pull/483)
- [(#483) Apply deno formatter/linter.](https://github.com/dajiaji/hpke-js/pull/483)
- [(#483) Fix type declaration error.](https://github.com/dajiaji/hpke-js/pull/483)
