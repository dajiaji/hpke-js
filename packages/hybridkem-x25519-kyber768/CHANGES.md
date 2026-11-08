# Changes

## Unreleased

## Version 1.7.1

Released 2026-11-08

- `encap()` and `decap()` now throw `NotSupportedError` when `senderKey` or
  `senderPublicKey`, respectively, is provided, rather than silently ignoring
  the sender key. Reported by Bhabani Sankar Das (@007bsd).

- Reduce bundle size by using the KEM identifier value directly instead of
  referencing the `KemId` object.

## Version 1.7.0

Released 2026-03-08

- [(#729) refactor(hybridkem-x25519-kyber768): use @hpke/common SHA3 and @hpke/core DhkemX25519.](https://github.com/dajiaji/hpke-js/pull/729)
- [(#728) perf(common): unroll SHA3/Keccak and simplify u64 and kyber utils.](https://github.com/dajiaji/hpke-js/pull/728)
- [(#724) chore(deps): bump TypeScript to ^5.9.3 in test and sample package.json.](https://github.com/dajiaji/hpke-js/pull/724)
- [(#718) refactor: add test:node prepare steps and use BufferSource in HPKE interfaces.](https://github.com/dajiaji/hpke-js/pull/718)
