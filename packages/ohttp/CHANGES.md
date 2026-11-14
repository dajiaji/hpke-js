# Changelog

## Version 0.2.0

Released 2026-11-14

- Change `createOhttpClient` to accept explicit KEM/KDF/AEAD instances and an
  injected `OhttpEncoding`. Replace `createOhttpServer` with
  `createOhttpGateway`, supplying its key pair explicitly.
- Change low-level encapsulation methods to exchange binary HTTP streams;
  contexts expose their payload through `body`.
- Export `createStandardEncoding` and `createChunkedEncoding` from the main
  `@hpke/ohttp` entry point. Both use the same binary HTTP stream API, and
  unused encodings and HTTP adapters can be excluded from bundles.
- Support draft-ietf-ohai-chunked-ohttp-08 with incremental encryption and
  decryption, authenticated final chunks, and configurable receive limits via
  `maxChunkSize` (16384 plaintext bytes per chunk by default).
- Export `ohttpFetch(client, input, init)` and `createOhttpGatewayHandler` from
  the main `@hpke/ohttp` entry point for Web Fetch requests and responses, with
  incremental binary HTTP conversion and cancellation of pending reads.
- Export `createOhttpKeyConfigHandler` to serve a gateway's key configuration as
  `application/ohttp-keys` from an independent Web Fetch handler.
- Export `createOhttpFetchForwarder`, a `forward` callback that fetches targets
  on allowed origins only, does not follow redirects, and removes the
  Content-Encoding and Content-Length headers of decoded response bodies.
- Add the `@hpke/ohttp/node` entry point with `toNodeListener`, which adapts a
  Web Fetch handler to a `node:http` request listener.
- Export `createOhttpRelayHandler`, a Web Fetch handler for a relay that
  forwards encapsulated requests to a configured gateway, passing on only the
  Content-Type and Incremental fields.
- Buffer relay uploads by default and allow streaming uploads with
  `streamingUpload: true`, independently of incremental response processing.
- Report response authentication failures as `OhttpError`, retaining the
  original failure as `cause`. Chunked responses can report these errors while
  their body is consumed.
- Validate key identifiers and binary HTTP request targets. The HTTP handler
  returns 400 for invalid encapsulated requests detected before responding,
  while unrelated upstream failures propagate.
- Select the first advertised key configuration matching the supplied KEM, KDF,
  and AEAD.

## Version 0.1.0

Released 2026-11-11

- Added Binary HTTP encoding and decoding for OHTTP requests and responses.
- Added suite negotiation for multiple KDF/AEAD pairs and key configurations.
- Added Deno and Node.js samples.
- Added client and server APIs for OHTTP request and response encapsulation.
