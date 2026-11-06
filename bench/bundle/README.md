# Bundle size benchmark

Measures minified, gzip (level 9), and brotli (quality 11) bundle sizes for
sender and recipient applications using a single fixed HPKE cipher suite.
`@hpke/core` and extension packages are bundled from the current repository
sources. Generated bundles are verified by sealing and opening a message.

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
```

Use `npm start -- --help` for all options and `npm run typecheck` to type-check
the tool.

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

## Bundlers

| Bundler | Configuration                                                |
| ------- | ------------------------------------------------------------ |
| esbuild | Bundle, minify, ESM, target ES2022                           |
| Rollup  | `@rollup/plugin-node-resolve` + `@rollup/plugin-terser`, ESM |
