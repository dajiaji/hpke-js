# Changes

## Version 1.9.0

Released 2026-03-08

- [(#718) refactor: add test:node prepare steps and use BufferSource in HPKE interfaces.](https://github.com/dajiaji/hpke-js/pull/718)
- [(#724) chore(deps): bump TypeScript to ^5.9.3 in test and sample package.json.](https://github.com/dajiaji/hpke-js/pull/724)
- [(#725) chore: exclude CHANGES.md from JSR publish and add .npmignore to npm packages.](https://github.com/dajiaji/hpke-js/pull/725)

## Version 1.8.0

Released 2026-03-01

- [(#700) chore(npm): bump @hpke/common to 1.9.0 and use ArrayBufferLike | ArrayBufferView instead of ArrayBuffer.](https://github.com/dajiaji/hpke-js/pull/700)
- [(#694) fix: derive public key without JWK export for Firefox compatibility.](https://github.com/dajiaji/hpke-js/pull/694)
- [(#695) test(browsers): use assertion timeout instead of fixed wait in Playwright specs.](https://github.com/dajiaji/hpke-js/pull/695)
- [(#685) test(core): simplify secure curves test with deriveKeyPair.](https://github.com/dajiaji/hpke-js/pull/685)
- [(#689) chore: update dependencies and deno task scripts.](https://github.com/dajiaji/hpke-js/pull/689)
- [(#680) base: update dependency of tests.](https://github.com/dajiaji/hpke-js/pull/680)
- [(#679) base: update dependency of samples.](https://github.com/dajiaji/hpke-js/pull/679)
- [(#683) docs: pnpm & yarn native jsr & double ats.](https://github.com/dajiaji/hpke-js/pull/683)
- core: document X25519 KEM support in core package.

## Version 1.7.5

Released 2025-11-19

- core: introduce mutex to protect nonce reuse. by @panva

## Version 1.7.4

Released 2025-08-14

- [(#625) base: add deno task test:browsers.](https://github.com/dajiaji/hpke-js/pull/625)
- [(#623) base: update test dependencies.](https://github.com/dajiaji/hpke-js/pull/623)
- [(#622) base: add deno task update.](https://github.com/dajiaji/hpke-js/pull/622)
- [(#617) base: add deno task dry-publish.](https://github.com/dajiaji/hpke-js/pull/617)
- [(#616) base: add deno task minify.](https://github.com/dajiaji/hpke-js/pull/616)
- [(#615) base: remove dependency on noble/hashes/sha3.](https://github.com/dajiaji/hpke-js/pull/615)
- [(#614) base: add deno task npm-build.](https://github.com/dajiaji/hpke-js/pull/614)
- [(#613) base: add deno task check.](https://github.com/dajiaji/hpke-js/pull/613)
- [(#610) base: remove path to noble from tsconfig.json.](https://github.com/dajiaji/hpke-js/pull/610)
- [(#565) core: add deriveKeyPair test for browsers.](https://github.com/dajiaji/hpke-js/pull/565)
- [(#563) core: run secure curves test on safari.](https://github.com/dajiaji/hpke-js/pull/563)
- [(#550) core: add DhkemX25519HkdfSha256 test for browsers.](https://github.com/dajiaji/hpke-js/pull/550)

## Version 1.7.3

Released 2025-07-12

- [(#527) base: bump @noble/cipher to 1.3.0](https://github.com/dajiaji/hpke-js/pull/527)
- [(#526) base: bump @hpke/core to 1.7.3](https://github.com/dajiaji/hpke-js/pull/526)
- [(#524) base: bump @hpke/common to 1.7.3](https://github.com/dajiaji/hpke-js/pull/524)

## Version 1.7.2

Released 2025-03-09

- [(#491) Remove package-lock.json for cloudflare test.](https://github.com/dajiaji/hpke-js/pull/491)
- [(#490) Update sample.](https://github.com/dajiaji/hpke-js/pull/490)
- [(#489) Bump @hpke/common to 1.7.2.](https://github.com/dajiaji/hpke-js/pull/489)
- [(#483) Apply deno formatter/linter.](https://github.com/dajiaji/hpke-js/pull/483)
- [(#483) Fix type declaration error.](https://github.com/dajiaji/hpke-js/pull/483)

## Version 1.7.1

Released 2024-11-08

- [(#472) Bump @hpke/common to 1.7.1.](https://github.com/dajiaji/hpke-js/pull/472)

## Version 1.7.0

Released 2024-11-06

- [(#463) Disclose JsonWebKeyExtended interface from @hpke/core.](https://github.com/dajiaji/hpke-js/pull/463)
