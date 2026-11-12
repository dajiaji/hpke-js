# Bundle size benchmark

Measures minified, gzip (level 9), and brotli (quality 11) bundle sizes for HPKE
sender and recipient applications using a single fixed cipher suite.
`@hpke/core` and extension packages are bundled from the current repository
sources. Generated bundles are verified by sealing and opening a message.

OHTTP client and gateway applications are also measured, including BHTTP
encoding and decoding and both directions of an HTTP exchange. OHTTP results are
reported separately from the panva HPKE comparison.

JOSE-HPKE Integrated Encryption (HPKE-3) measures `@hpke/jose` from the current
repository sources. The sender imports a public JWK and encrypts a Compact JWE;
the recipient imports a private JWK and decrypts it, using `createJoseHpke3()`
with `seal()` / `open()`. Each application is bundled independently, and the
generated bundles are verified by a round-trip for each bundler. Key generation
is outside the measured application bundles.

Like OHTTP, JOSE has its own minified / gzip / brotli size tables and JSON
results, without a panva comparison or size ratios. Sample entry sources are
defined in [`src/jose.ts`](./src/jose.ts).

## Usage

Requires Node.js >= 24 and npm.

```sh
cd bench/bundle
npm ci
npm run bench
```

Results are written to `results.md` and `results.json`, which are ignored by
Git.

To select suites or a bundler, or inspect module sizes:

```sh
npm start -- --filter x25519 --bundler rollup
npm start -- --filter p256 --bundler esbuild --analyze
npm start -- --filter ohttp --analyze
npm start -- --filter jose
```

Use `npm start -- --help` for all options and `npm run typecheck` to type-check
the tool.

To compare OHTTP results with a previously measured source state, save its
`results.json` and pass it to the new run:

```sh
npm run bench -- --compare baseline/results.json
```

The console, Markdown and JSON reports include before/after sizes for each role
and bundler. Use the same benchmark, dependency lockfile and Node version for
both runs. A before/after source comparison must keep unrelated working-tree
changes identical; it must not substitute the published package for one side.

## Cipher suites

Each suite is measured for both sender and recipient roles. Definitions are in
[`src/suites.ts`](./src/suites.ts).

| KEM                        | KDF         | AEAD             |
| -------------------------- | ----------- | ---------------- |
| DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-128-GCM      |
| DHKEM(P-384, HKDF-SHA384)  | HKDF-SHA384 | AES-256-GCM      |
| DHKEM(P-521, HKDF-SHA512)  | HKDF-SHA512 | AES-256-GCM      |
| DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM      |
| DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20Poly1305 |
| DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | AES-256-GCM      |
| ML-KEM-768                 | HKDF-SHA256 | AES-128-GCM      |
| X-Wing (MLKEM768-X25519)   | HKDF-SHA256 | AES-128-GCM      |

## OHTTP

| KEM package          | KDF / AEAD from `@hpke/core` |
| -------------------- | ---------------------------- |
| `@hpke/dhkem-x25519` | HKDF-SHA256 / AES-128-GCM    |
| `@hpke/dhkem-x448`   | HKDF-SHA512 / AES-256-GCM    |

These configurations follow the OHTTP sample: the KEM uses an extension package,
whose internal HKDF previously pulled in the JavaScript HMAC/SHA-2 fallback. The
application KDF uses core's native implementation.

- **client**: imports the gateway key configuration, encrypts the HTTP request,
  and decrypts the HTTP response.
- **gateway** (Oblivious Gateway Resource, created by `createOhttpServer()`):
  imports existing private/public keys, publishes the key configuration,
  decrypts the HTTP request, and encrypts the HTTP response.

OHTTP role names follow
[RFC 9458, Section 2.2](https://www.rfc-editor.org/rfc/rfc9458.html#section-2.2).
The relay and target applications are outside these bundles. Earlier baseline
JSON files using `sender` / `recipient` remain accepted by `--compare` and are
normalized to `client` / `gateway`. HPKE suite labels remain `sender` /
`recipient`.

Verification checks the request method, URL, header and body and the response
status, header and body. With `--keep`, the bundles remain in `dist/` and can
also be checked across two source versions with `verifyOhttp()`.

## Bundlers

| Bundler | Configuration                                                                         |
| ------- | ------------------------------------------------------------------------------------- |
| esbuild | Bundle, minify, ESM, target ES2022                                                    |
| Rollup  | `@rollup/plugin-node-resolve` + `@rollup/plugin-terser`, ESM, dynamic imports inlined |
