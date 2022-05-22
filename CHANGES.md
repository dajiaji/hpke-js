# Changes

## Unreleased

## Version 0.7.1

Released 2022-05-22

- [(#42) Reject all-zero shared secret derived with X25519.](https://github.com/dajiaji/hpke-js/pull/42)
- [(#42) Add tests for key validation.](https://github.com/dajiaji/hpke-js/pull/42)

## Version 0.7.0

Released 2022-05-21

- [(#40) Add support for DHKEM(X25519, HKDF-SHA256).](https://github.com/dajiaji/hpke-js/pull/40)

## Version 0.6.0

Released 2022-05-21

- [(#38) Add support for ChaCha20/Poly1305.](https://github.com/dajiaji/hpke-js/pull/38)
- [(#37) [Breaking Change] Remove redundant output from dist.](https://github.com/dajiaji/hpke-js/pull/37)

## Version 0.5.1

Released 2022-05-16

- [(#32) Release typedoc API document.](https://github.com/dajiaji/hpke-js/pull/32)

## Version 0.5.0

Released 2022-05-15

- [(#30) Add support for deriveKeyPair.](https://github.com/dajiaji/hpke-js/pull/30)
- [(#30) [Breaking Change] Remove deriveKey.](https://github.com/dajiaji/hpke-js/pull/30)
- [(#29) Fix upper limit check for sequence number of encryption.](https://github.com/dajiaji/hpke-js/pull/29)
- [(#28) Improve test coverage.](https://github.com/dajiaji/hpke-js/pull/28)
- [(#25) Add SerializeError.](https://github.com/dajiaji/hpke-js/pull/25)
- [(#25) Enable lint test on github action.](https://github.com/dajiaji/hpke-js/pull/25)
- [(#25) Introduce KemPrimitives to make it easy to add KEM algorithms.](https://github.com/dajiaji/hpke-js/pull/25)
- [(#24) Introduce AeadKey interface to make it easy to add new AEAD algorithms.](https://github.com/dajiaji/hpke-js/pull/24)

## Version 0.4.1

Released 2022-05-12

- [(#22) Refine dist structure.](https://github.com/dajiaji/hpke-js/pull/22)

## Version 0.4.0

Released 2022-05-10

- [(#20) Add samples to README.](https://github.com/dajiaji/hpke-js/pull/20)
- [(#19) Fix bug on browser environment.](https://github.com/dajiaji/hpke-js/pull/19)
- [(#18) Change the default test environment from jsdom to node.](https://github.com/dajiaji/hpke-js/pull/18)
- [(#16) Add support for bidirectional environment.](https://github.com/dajiaji/hpke-js/pull/16)

## Version 0.3.1

Released 2022-05-08

- [(#14) Add support for deriveKey.](https://github.com/dajiaji/hpke-js/pull/14)
- [(#14) Fix bug on extract.](https://github.com/dajiaji/hpke-js/pull/14)

## Version 0.3.0

Released 2022-05-08

- [(#11) Add support for single-shot apis.](https://github.com/dajiaji/hpke-js/pull/11)

## Version 0.2.4

Released 2022-05-07

- [(#9) Allow to use privateKey as senderKey and recipientKey parameter.](https://github.com/dajiaji/hpke-js/pull/9)
- Fix bug on [#7](https://github.com/dajiaji/hpke-js/pull/7).

## Version 0.2.3

Released 2022-05-07

- [(#7) Add \*.{ts, d.ts, d.ts.map} to npm package.](https://github.com/dajiaji/hpke-js/pull/7)

## Version 0.2.2

Released 2022-05-06

- Fix bug on using Web Crypto API on Node.js environment.

## Version 0.2.1

Released 2022-05-06

- Add support for Node.js environment.

## Version 0.2.0

Released 2022-05-06

- First public preview release.
