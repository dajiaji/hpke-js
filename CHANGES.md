# Changes

## Version 1.2.8

Released 2024-08-04

- [(#307) Add config to deno test on test/runtimes/cloudflare.](https://github.com/dajiaji/hpke-js/pull/307)
- [(#305) Fix ekm byte length typo in Hybrid KEM.](https://github.com/dajiaji/hpke-js/pull/305)
- [(#303) Fix linter/formatter error on samples/ts-webpack.](https://github.com/dajiaji/hpke-js/pull/303)
- [(#301) Add webpack sample.](https://github.com/dajiaji/hpke-js/pull/301)
- Update dependencies:
  - [(#308) Bump @noble/curves to 1.4.2.](https://github.com/dajiaji/hpke-js/pull/308)
  - [(#308) Bump @noble/hashes to 1.4.0.](https://github.com/dajiaji/hpke-js/pull/308)
  - [(#308) Bump @noble/ciphers to 0.5.3.](https://github.com/dajiaji/hpke-js/pull/308)
- Update devDependencies:
  - [(#308) Bump ts-webpack dependencies.](https://github.com/dajiaji/hpke-js/pull/308)
  - [(#308) Bump @playwright/test to 1.45.3.](https://github.com/dajiaji/hpke-js/pull/308)
  - [(#308) Bump wrangler to 3.68.0.](https://github.com/dajiaji/hpke-js/pull/308)
  - [(#308) Bump dnt to 0.40.0.](https://github.com/dajiaji/hpke-js/pull/308)
  - [(#308) Bump std to 0.224.0.](https://github.com/dajiaji/hpke-js/pull/308)

## Version 1.2.7

Released 2024-01-28

- Update dependencies:
  - [(#299) Bump @noble/curves to 1.3.0.](https://github.com/dajiaji/hpke-js/pull/299)

## Version 1.2.6

Released 2024-01-28

- [(#294) Add support for importKey for P-521 public key on Deno.](https://github.com/dajiaji/hpke-js/pull/293)
- [(#293) Fix test to follow Deno update.](https://github.com/dajiaji/hpke-js/pull/293)
- [(#293) Add noEmit to tsconfig.json.](https://github.com/dajiaji/hpke-js/pull/293)
- Update dependencies:
  - [(#296) Bump @noble/hashes to 1.3.3.](https://github.com/dajiaji/hpke-js/pull/296)
  - [(#296) Bump @noble/ciphers to 0.4.1.](https://github.com/dajiaji/hpke-js/pull/296)
- Update devDependencies:
  - [(#295) Bump dnt to 0.39.0 (for core/ and x/).](https://github.com/dajiaji/hpke-js/pull/295)
  - [(#295) Bump playwright/test to 1.41.1.](https://github.com/dajiaji/hpke-js/pull/295)
  - [(#295) Bump Wrangler to 3.19.0.](https://github.com/dajiaji/hpke-js/pull/295)
  - [(#295) Bump deno.land/std to 0.213.0.](https://github.com/dajiaji/hpke-js/pull/295)

## Version 1.2.5

Released 2023-11-26

- [(#291) Make dnt emit type declaration inline.](https://github.com/dajiaji/hpke-js/pull/291)
- Update workflows:
  - [(#289) Loosen bun versions on CI.](https://github.com/dajiaji/hpke-js/pull/289)
  - [(#289) Add Node 21 to CI.](https://github.com/dajiaji/hpke-js/pull/289)
  - [(#289) Bump actions/checkout to v4.](https://github.com/dajiaji/hpke-js/pull/289)
  - [(#289) Bump actions/setup-node to v4.](https://github.com/dajiaji/hpke-js/pull/289)
- Update devDependencies:
  - [(#291) Bump deno.land/std to 0.208.0.](https://github.com/dajiaji/hpke-js/pull/291)
  - [(#291) Bump deno.land/x/dnt to 0.39.0.](https://github.com/dajiaji/hpke-js/pull/291)

## Version 1.2.4

Released 2023-11-05

- [(#288) Unlock the version of Deno on CI for cloudflare workers and bun.](https://github.com/dajiaji/hpke-js/pull/288)
- [(#288) Bump @noble/ciphers to 0.4.0.](https://github.com/dajiaji/hpke-js/pull/288)
- [(#285) Add test for bidirectional encryption.](https://github.com/dajiaji/hpke-js/pull/285)

## Version 1.2.3

Released 2023-09-09

- [(#282) Update devDependencies.](https://github.com/dajiaji/hpke-js/pull/282)
- [(#281) Bump @noble/ciphers to 0.3.0.](https://github.com/dajiaji/hpke-js/pull/281)
- [(#280) Bump @noble/curves to 1.2.0.](https://github.com/dajiaji/hpke-js/pull/280)
- [(#279) Bump @noble/hashes to 1.3.2.](https://github.com/dajiaji/hpke-js/pull/279)
- [(#279) Sync kyber implementation to crystals-kyber-js.](https://github.com/dajiaji/hpke-js/pull/279)
- [(#275) Add BaseError/KyberError.](https://github.com/dajiaji/hpke-js/pull/275)

## Version 1.2.2

Released 2023-08-20

- [(#273) Add docstring for tsdoc.](https://github.com/dajiaji/hpke-js/pull/273)
- [(#272) Refactor kyber.](https://github.com/dajiaji/hpke-js/pull/272)
- [(#271) Introduce constantTimeCompare to kyber.](https://github.com/dajiaji/hpke-js/pull/271)
- [(#270) Update loadSubtleCrypto/loadCrypto.](https://github.com/dajiaji/hpke-js/pull/270)

## Version 1.2.1

Released 2023-08-19

- [(#264) Refine READMEs.](https://github.com/dajiaji/hpke-js/pull/264)
- [(#263) Add support for the hybrid post-quantum KEM (X25519Kyber768Draft00) experimentally.](https://github.com/dajiaji/hpke-js/pull/263)

## Version 1.2.0

Released 2023-08-16

- [(#261) BREAKING CHANGE on hpke/core: Drop KemId/KdfId/AeadId support from CipherSuiteNative.](https://github.com/dajiaji/hpke-js/pull/261)

## Version 1.1.1

Released 2023-08-15

- [(#259) Remove imports with asterisk.](https://github.com/dajiaji/hpke-js/pull/259)
- [(#258) Add sideEffects:false to dnt.ts.](https://github.com/dajiaji/hpke-js/pull/258)

## Version 1.1.0

Released 2023-08-15

- [(#256) Remove unused utilities.](https://github.com/dajiaji/hpke-js/pull/256)
- [(#251) Refactor KEM implementation.](https://github.com/dajiaji/hpke-js/pull/251)
- [(#251) Add NativeAlgorithm as base class for cryptographic algorithms using Web Cryptography API.](https://github.com/dajiaji/hpke-js/pull/251)
- [(#251) Add KemId.NotAssigned.](https://github.com/dajiaji/hpke-js/pull/251)
- [(#250) Use deno-fmt-ignore for const byte string.](https://github.com/dajiaji/hpke-js/pull/250)
- [(#249) Add serialize/deserializePrivatekey to KemInterface.](https://github.com/dajiaji/hpke-js/pull/249)

## Version 1.0.4

Released 2023-08-11

- [(#246) Remove api parameter from KdfInterface.init().](https://github.com/dajiaji/hpke-js/pull/246)
- [(#245) Remove init() from AeadInterface.](https://github.com/dajiaji/hpke-js/pull/245)
- [(#244) Remove init() from KemInterface.](https://github.com/dajiaji/hpke-js/pull/244)
- [(#240) Refactor DhkemSecp256k1HkdfSha256.](https://github.com/dajiaji/hpke-js/pull/240)
- [(#239) Bump noble/ciphers to 0.2.0.](https://github.com/dajiaji/hpke-js/pull/239)

## Version 1.0.3

Released 2023-08-07

- [(#237) Separate consts to minimize the size of submodules.](https://github.com/dajiaji/hpke-js/pull/237)
- [(#236) Update dnt config.](https://github.com/dajiaji/hpke-js/pull/236)
- [(#235) Fix unnecessary disclosure for AesGcm classes.](https://github.com/dajiaji/hpke-js/pull/235)
- [(#232) Remove tsdoc remarks.](https://github.com/dajiaji/hpke-js/pull/232)

## Version 1.0.2

Released 2023-08-06

- [(#230) Simplify and expose HpkeError.](https://github.com/dajiaji/hpke-js/pull/230)
- [(#229) Rename \*ContextInterface to \*Context.](https://github.com/dajiaji/hpke-js/pull/229)
- [(#227) Refine tsdoc description.](https://github.com/dajiaji/hpke-js/pull/227)

## Version 1.0.1

Released 2023-08-06

- [(#226) Remove unnecessary ciphersuite classes.](https://github.com/dajiaji/hpke-js/pull/226)
- [(#225) Deploy tsdoc-based document to pages.](https://github.com/dajiaji/hpke-js/pull/225)

## Version 1.0.0

Released 2023-08-05

- [(#222) Increase the input limits from 128 bytes to 8192 bytes.](https://github.com/dajiaji/hpke-js/pull/222)
  by @snorp
- [(#220) Add hpke/chacha20poly1305.](https://github.com/dajiaji/hpke-js/pull/220)
- [(#219) Add hpke/dhkem-x448.](https://github.com/dajiaji/hpke-js/pull/219)
- [(#218) Update dhkem-secp256k1 test to use hpke/core.](https://github.com/dajiaji/hpke-js/pull/218)
- [(#217) Add hpke/dhkem-x25519.](https://github.com/dajiaji/hpke-js/pull/217)
- [(#216) Add hpke/core.](https://github.com/dajiaji/hpke-js/pull/216)
- [(#215) Expose CipherSuiteNative class for hpke-js.](https://github.com/dajiaji/hpke-js/pull/215)
- [(#214) BREAKING CHANGES for 1.0.0.](https://github.com/dajiaji/hpke-js/pull/214)
  - Change CipherSuite.kem/kdf/aead to CipherSuite.kem.id/kdf.id/aead.id.
  - Remove KemId.DhkemSecp256"K"1HkdfSha256.
  - Remove CipherSuite.kemContext(). (Use CipherSuite.kem)
  - Remove CipherSuite.kdfContext(). (Use CipherSuite.kdf)
  - Remove createAeadKey from CipherSuite. (Use
    CipherSuite.aead.createEncryptionContext())
  - Rename AeadKey to AeadEncryptionContext.
  - Simplify AeadEncryptionContext interface.
  - Drop support for bi-drectional encryption.
- [(#213) Update x/dhkem-secp256k1/deno.json.](https://github.com/dajiaji/hpke-js/pull/213)
- [(#212) Separate the HKDF classes dependent on external modules from the independent base class.](https://github.com/dajiaji/hpke-js/pull/212)
- [(#211) Separate dhkemPrimitives from dhkem classes.](https://github.com/dajiaji/hpke-js/pull/211)

## Version 0.22.2

Released 2023-07-28

- [(#208) Fix encSize and publicKeySize of DhkemSecp256k1HkdfSha256.](https://github.com/dajiaji/hpke-js/pull/208)

## Version 0.22.1

Released 2023-07-28

- [(#206) Change scoped package name.](https://github.com/dajiaji/hpke-js/pull/206)

## Version 0.22.0

Released 2023-07-27

- [(#199) Add common server for testing.](https://github.com/dajiaji/hpke-js/pull/199)
- [(#196) BREAKING: Separate dhkemSecp256k1HkdfSha256 from core module.](https://github.com/dajiaji/hpke-js/pull/196)
- Update dev dependencies:
  - [(#201) Bump undici to 5.22.1.](https://github.com/dajiaji/hpke-js/pull/201)

## Version 0.21.0

Released 2023-07-25

- [(#194) Expose AEAD Classes for CipherSuiteParams.](https://github.com/dajiaji/hpke-js/pull/194)
- [(#193) Add AeadInterface for CipherSuiteParams.](https://github.com/dajiaji/hpke-js/pull/193)
- [(#192) Add mod.ts to formatter/linter targets.](https://github.com/dajiaji/hpke-js/pull/192)
- [(#191) Update CipherSuiteParameters to make Kem/KdfInterface to be set instead of Kem/KdfId.](https://github.com/dajiaji/hpke-js/pull/191)
- [(#190) Introduce union type algorithm identifier.](https://github.com/dajiaji/hpke-js/pull/190)
- [(#189) Add support for Node.js 20.](https://github.com/dajiaji/hpke-js/pull/189)

## Version 0.20.0

Released 2023-07-19

- [(#187) Use noble/curves/secp256k1 instead of noble/secp256k1.](https://github.com/dajiaji/hpke-js/pull/187)
- [(#186) Update deno.json not to use 'files'.](https://github.com/dajiaji/hpke-js/pull/186)
- [(#185) Refactor KEM/KDF/AEAD constructor.](https://github.com/dajiaji/hpke-js/pull/185)

## Version 0.19.0

Released 2023-07-17

- [(#183) Add support for importKey('jwk').](https://github.com/dajiaji/hpke-js/pull/183)
- [(#181) Adopt noble-ciphers insterad of standardlib for ChaCha20/Poly1305.](https://github.com/dajiaji/hpke-js/pull/181)
- [(#178) Merge import-map into deno.json.](https://github.com/dajiaji/hpke-js/pull/178)
- Update dev dependencies:
  - [(#180) Bump @playwright/test to 1.36.1.](https://github.com/dajiaji/hpke-js/pull/180)

## Version 0.18.5

Released 2023-06-13

- [(#172) Add deno.lock.](https://github.com/dajiaji/hpke-js/pull/172)
- [(#170) Drop support for nest.land.](https://github.com/dajiaji/hpke-js/pull/170)
- Update dev dependencies:
  - [(#171) Bump deno/std to 0.191.0.](https://github.com/dajiaji/hpke-js/pull/171)
  - [(#171) Bump deno/dnt to 0.37.0.](https://github.com/dajiaji/hpke-js/pull/171)

## Version 0.18.4

Released 2023-06-13

- [(#165) Use audited version of noble/curves.](https://github.com/dajiaji/hpke-js/pull/165)
- [(#163) Fix a typo in the CipherSuite.ts.](https://github.com/dajiaji/hpke-js/pull/163)
- Update dev dependencies:
  - [(#162) Bump @playwright/test to 1.35.0.](https://github.com/dajiaji/hpke-js/pull/162)

## Version 0.18.3

Released 2023-04-08

- [(#155) Fix TypeScript compile error.](https://github.com/dajiaji/hpke-js/pull/155)
- [(#148) Add SECURITY.md.](https://github.com/dajiaji/hpke-js/pull/148)
- Update dev dependencies:
  - [(#154) Bump @playwright/test to 1.32.2.](https://github.com/dajiaji/hpke-js/pull/154)
  - [(#148) Bump wrangler to 2.10.0.](https://github.com/dajiaji/hpke-js/pull/148)
  - [(#146) Bump http-cache-semantics to 4.1.1.](https://github.com/dajiaji/hpke-js/pull/146)

## Version 0.18.2

Released 2023-01-17

- [(#143) Do not use import-map for npm module.](https://github.com/dajiaji/hpke-js/pull/143)

## Version 0.18.1

Released 2023-01-17

- [(#141) Allow to use over hash size length key for SHA384.](https://github.com/dajiaji/hpke-js/pull/141)
- [(#140) Use noble/hashes for HDKF fallback process.](https://github.com/dajiaji/hpke-js/pull/140)

## Version 0.18.0

Released 2023-01-16

- [(#138) Use noble/curves for x25519/x448.](https://github.com/dajiaji/hpke-js/pull/138)

## Version 0.17.2

Released 2023-01-16

- [(#136) Use audited secp256k1 lib.](https://github.com/dajiaji/hpke-js/pull/136)
- [(#135) Refine the table of supported runtimes.](https://github.com/dajiaji/hpke-js/pull/135)
- [(#134) Add support for bun.](https://github.com/dajiaji/hpke-js/pull/134)
- [(#132) Activate DHKEM P-384 test for Deno.](https://github.com/dajiaji/hpke-js/pull/132)
- [(#130) Add npm package to import-map.json.](https://github.com/dajiaji/hpke-js/pull/130)
- [(#125) Add dependabot.yml.](https://github.com/dajiaji/hpke-js/pull/125)
- Update dev dependencies:
  - [(#131) Bump wrangler to 2.7.1.](https://github.com/dajiaji/hpke-js/pull/131)
  - [(#126) Bump @playwright/test to 1.29.2.](https://github.com/dajiaji/hpke-js/pull/126)

## Version 0.17.1

Released 2023-01-05

- [(#123) Add secp256k1 test for Cloudflare Workers.](https://github.com/dajiaji/hpke-js/pull/123)
- [(#122) Fix error on release process for egg.](https://github.com/dajiaji/hpke-js/pull/122)

## Version 0.17.0

Released 2023-01-05

- [(#121) Bump deno/std to 0.170.0.](https://github.com/dajiaji/hpke-js/pull/121)
- [(#120) Add support for DHKEM(secp256k1, HKDF-SHA256) experimentally.](https://github.com/dajiaji/hpke-js/pull/120)

## Version 0.16.0

Released 2023-01-04

- [(#118) Refine KDF Interface.](https://github.com/dajiaji/hpke-js/pull/118)
- [(#117) Refine KDF Interface.](https://github.com/dajiaji/hpke-js/pull/117)
- [(#116) Refine KEM Interface.](https://github.com/dajiaji/hpke-js/pull/116)
- [(#112) Remove bundles.](https://github.com/dajiaji/hpke-js/pull/112)
- [(#107) Add Node.js v19 to CI.](https://github.com/dajiaji/hpke-js/pull/107)
- [(#106) Fix import path to deno.land on README.](https://github.com/dajiaji/hpke-js/pull/106)

## Version 0.15.0

Released 2022-11-06

- [(#103) Disclose KEM attributes.](https://github.com/dajiaji/hpke-js/pull/103)

## Version 0.14.0

Released 2022-10-28

- [(#101) Expose suite-specific KDF and AEAD interface.](https://github.com/dajiaji/hpke-js/pull/101)
- [(#98) Replace deno test jobs with parallel.](https://github.com/dajiaji/hpke-js/pull/98)
- [(#94) Add edge and chrome to playwright test projects.](https://github.com/dajiaji/hpke-js/pull/94)
- [(#93) Add cov to deno tasks.](https://github.com/dajiaji/hpke-js/pull/93)
- [(#92) Introduce import-map.](https://github.com/dajiaji/hpke-js/pull/92)
- [(#91) Refine deno.json.](https://github.com/dajiaji/hpke-js/pull/91)
- [(#90) Add the minimum supported versions to README.](https://github.com/dajiaji/hpke-js/pull/90)

## Version 0.13.0

Released 2022-07-01

- [(#88) Add support for Cloudflare Workers.](https://github.com/dajiaji/hpke-js/pull/88)

## Version 0.12.1

Released 2022-07-01

- [(#86) Ship hpke.min.js.](https://github.com/dajiaji/hpke-js/pull/86)

## Version 0.12.0

Released 2022-06-26

- [(#84) BREAKING: Use git tags for versioning.](https://github.com/dajiaji/hpke-js/pull/84)
- [(#83) Ship to nest.land.](https://github.com/dajiaji/hpke-js/pull/83)
- [(#82) Add fmt and lint to deno tasks.](https://github.com/dajiaji/hpke-js/pull/82)

## Version 0.11.5

Released 2022-06-18

- [(#76) Add DHKEM(P-256, HKDF-SHA256) to Deno supported KEMs.](https://github.com/dajiaji/hpke-js/pull/78)

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
- [(#60) BREAKING: Drop hpke.min.js and hpke.js support.](https://github.com/dajiaji/hpke-js/pull/60)

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
- [(#47) BREAKING: Add minimum length check for PSK.](https://github.com/dajiaji/hpke-js/pull/47)
- [(#46) Add importKey to CipherSuite.](https://github.com/dajiaji/hpke-js/pull/46)
- [(#45) BREAKING: Add input length validation.](https://github.com/dajiaji/hpke-js/pull/45)

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
- [(#37) BREAKING: Remove redundant output from dist.](https://github.com/dajiaji/hpke-js/pull/37)

## Version 0.5.1

Released 2022-05-16

- [(#32) Release typedoc API document.](https://github.com/dajiaji/hpke-js/pull/32)

## Version 0.5.0

Released 2022-05-15

- [(#30) Add support for deriveKeyPair.](https://github.com/dajiaji/hpke-js/pull/30)
- [(#30) BREAKING: Remove deriveKey.](https://github.com/dajiaji/hpke-js/pull/30)
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
