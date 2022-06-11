# Changes

## Unreleased

## Version 0.11.4

Released 2022-06-11

- [(#76) Add playwright test.](https://github.com/dajiaji/hpke-js/pull/76)
- [(#75) Refine dnt.ts.](https://github.com/dajiaji/hpke-js/pull/75)
- [(#74) Add Github pages for test.](https://github.com/dajiaji/hpke-js/pull/74)

## Version 0.11.3

Released 2022-06-09

- [(#72) Add test for browsers.](https://github.com/dajiaji/hpke-js/pull/72)
- [(#71) Refine samples](https://github.com/dajiaji/hpke-js/pull/71)

## Version 0.11.2

Released 2022-06-07

- [(#68) Add test.](https://github.com/dajiaji/hpke-js/pull/68)
- [(#67) Refine deno.json.](https://github.com/dajiaji/hpke-js/pull/67)

## Version 0.11.1

Released 2022-06-06

- [(#63) Add coverage setting.](https://github.com/dajiaji/hpke-js/pull/63)
- [Remove @link from jsdoc string.](https://github.com/dajiaji/hpke-js/commit/829602fda65c16e0d770e9d758beee23ac9bc7b6)
- [Refine jsdoc string.](https://github.com/dajiaji/hpke-js/commit/86e5bb555b7502986c177ebb0fbdcbfea93edf1b)

## Version 0.11.0

Released 2022-06-06

- [(#61) Drop typedoc support.](https://github.com/dajiaji/hpke-js/pull/61)
- [(#60) [Breaking Change] Drop hpke.min.js and hpke.js support.](https://github.com/dajiaji/hpke-js/pull/60)

## Version 0.10.2

Released 2022-06-05

- [(#58) Fix bug on publish.yml.](https://github.com/dajiaji/hpke-js/pull/58)

## Version 0.10.1

Released 2022-06-05

- [(#57) Fix bug on publish.yml.](https://github.com/dajiaji/hpke-js/pull/57)

## Version 0.10.0

Released 2022-06-05

- [(#55) Add support for Deno.](https://github.com/dajiaji/hpke-js/pull/55)

## Version 0.9.1

Released 2022-05-29

- [(#53) Remove 'deriveKey' from key usages.](https://github.com/dajiaji/hpke-js/pull/53)
- [(#53) Flush internal buffer for secrets.](https://github.com/dajiaji/hpke-js/pull/53)
- [(#52) Add supported environments to README.](https://github.com/dajiaji/hpke-js/pull/52)

## Version 0.9.0

Released 2022-05-28

- [(#50) Add support for DHKEM(X448, HKDF-SHA512).](https://github.com/dajiaji/hpke-js/pull/50)
- [(#49) Optimize suite\_id generation.](https://github.com/dajiaji/hpke-js/pull/49)

## Version 0.8.0

Released 2022-05-24

- [(#47) Refine typedoc description.](https://github.com/dajiaji/hpke-js/pull/47)
- [(#47) [Breaking Change] Add minimum length check for PSK.](https://github.com/dajiaji/hpke-js/pull/47)
- [(#46) Add importKey to CipherSuite.](https://github.com/dajiaji/hpke-js/pull/46)
- [(#45) [Breaking Change] Add input length validation.](https://github.com/dajiaji/hpke-js/pull/45)

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
