import type { CipherSuite } from "@hpke/core";

import type { OhttpEncoding } from "./encoding.ts";
import { ByteReader, concat, encodeInteger, stream } from "./streams.ts";
import { buildHeader, deriveResponseKeyNonce } from "./responseKeys.ts";
import { decryptResponse, OhttpError } from "./errors.ts";

const FINAL = new TextEncoder().encode("final");
const RESPONSE = new TextEncoder().encode("message/bhttp chunked response");

function info(header: Uint8Array): Uint8Array {
  return concat([
    new TextEncoder().encode("message/bhttp chunked request"),
    new Uint8Array(1),
    header,
  ]);
}

type Crypt = (data: Uint8Array, aad: Uint8Array) => Promise<ArrayBuffer>;

async function* seal(
  reader: ByteReader,
  crypt: Crypt,
): AsyncGenerator<Uint8Array> {
  // Always emit an authenticated empty final chunk, avoiding lookahead latency.
  for await (const input of reader.rest()) {
    for (let offset = 0; offset < input.length; offset += 16384) {
      const ct = new Uint8Array(
        await crypt(input.subarray(offset, offset + 16384), new Uint8Array(0)),
      );
      yield concat([encodeInteger(ct.length), ct]);
    }
  }
  yield concat([
    new Uint8Array(1),
    new Uint8Array(await crypt(new Uint8Array(0), FINAL)),
  ]);
}

async function* open(
  reader: ByteReader,
  crypt: Crypt,
  maxCiphertext: number,
): AsyncGenerator<Uint8Array> {
  try {
    for (;;) {
      const length = (await reader.integer())!;
      const last = length === 0;
      if (length > maxCiphertext) {
        throw new OhttpError("Chunk exceeds configured size limit");
      }
      const parts: Uint8Array[] = [];
      let size = 0;
      if (last) {
        for await (const part of reader.rest()) {
          size += part.length;
          if (size > maxCiphertext) {
            throw new OhttpError("Final chunk exceeds configured size limit");
          }
          parts.push(part);
        }
      }
      const ct = last ? concat(parts) : await reader.read(length);
      const pt = new Uint8Array(
        await crypt(ct, last ? FINAL : new Uint8Array(0)),
      );
      if (!last && !pt.length) throw new OhttpError("Empty non-final chunk");
      if (pt.length) yield pt;
      if (last) return;
    }
  } finally {
    await reader.close();
  }
}

async function responseCrypt(
  suite: CipherSuite,
  enc: Uint8Array,
  responseNonce: Uint8Array,
  exporter: (label: Uint8Array, size: number) => Promise<ArrayBuffer>,
  decrypt: boolean,
): Promise<Crypt> {
  const secret = new Uint8Array(
    await exporter(
      RESPONSE,
      Math.max(suite.aead.keySize, suite.aead.nonceSize),
    ),
  );
  const { key, nonce } = await deriveResponseKeyNonce(
    suite,
    enc,
    responseNonce,
    secret,
  );
  const ctx = suite.aead.createEncryptionContext(key);
  let counter = 0n;
  return (data, aad) => {
    if (counter >= (1n << BigInt(8 * suite.aead.nonceSize)) - 1n) {
      throw new OhttpError("Chunk counter exhausted");
    }
    const iv = new Uint8Array(nonce.slice(0));
    let value = counter++;
    for (let i = iv.length - 1; i >= 0; --i) {
      iv[i] ^= Number(value & 255n);
      value >>= 8n;
    }
    return decrypt
      ? decryptResponse(() => ctx.open(iv, data, aad))
      : ctx.seal(iv, data, aad);
  };
}

/** Receiver limits for chunked OHTTP. */
export interface OhttpChunkedEncodingOptions {
  /** Maximum plaintext bytes per received chunk, including the final chunk.
   * Defaults to 16384. Must be at least 16384 to meet draft-08 requirements.
   */
  maxChunkSize?: number;
}

/** Chunked OHTTP draft-08 encoding with incremental processing. */
export function createChunkedEncoding(
  options: OhttpChunkedEncodingOptions = {},
): OhttpEncoding {
  const maxChunkSize = options.maxChunkSize ?? 16384;
  if (
    !Number.isSafeInteger(maxChunkSize) || maxChunkSize < 16384 ||
    maxChunkSize > Number.MAX_SAFE_INTEGER - 65536
  ) {
    throw new OhttpError(
      "maxChunkSize must be a safe integer of at least 16384",
    );
  }
  const requestContentType = "message/ohttp-chunked-req";
  const responseContentType = "message/ohttp-chunked-res";
  return {
    requestContentType,
    responseContentType,
    incremental: true,
    async encapsulateRequest(suite, keyId, key, source) {
      const header = buildHeader(
        keyId,
        suite.kem.id,
        suite.kdf.id,
        suite.aead.id,
      );
      const ctx = await suite.createSenderContext({
        recipientPublicKey: key,
        info: info(header),
      });
      const enc = new Uint8Array(ctx.enc);
      const reader = new ByteReader(source);
      let used = false;
      return {
        body: stream(
          (async function* () {
            yield concat([header, enc]);
            yield* seal(reader, (data, aad) => ctx.seal(data, aad));
          })(),
          () => reader.close(),
        ),
        contentType: requestContentType,
        async decapsulateResponse(source) {
          if (used) throw new OhttpError("Response already consumed");
          used = true;
          const response = new ByteReader(source);
          try {
            const nonce = await response.read(
              Math.max(suite.aead.keySize, suite.aead.nonceSize),
            );
            const crypt = await responseCrypt(
              suite,
              enc,
              nonce,
              (label, n) => ctx.export(label, n),
              true,
            );
            return stream(
              open(response, crypt, maxChunkSize + suite.aead.tagSize),
              () => response.close(),
            );
          } catch (error) {
            await response.close();
            throw error;
          }
        },
      };
    },
    async decapsulateRequest(suite, keyId, key, source) {
      const reader = new ByteReader(source);
      try {
        const header = await reader.read(7);
        const expected = buildHeader(
          keyId,
          suite.kem.id,
          suite.kdf.id,
          suite.aead.id,
        );
        if (!header.every((b, i) => b === expected[i])) {
          throw new OhttpError("Chunked request configuration mismatch");
        }
        const enc = await reader.read(suite.kem.encSize);
        const ctx = await suite.createRecipientContext({
          recipientKey: key,
          enc,
          info: info(header),
        });
        let used = false;
        return {
          body: stream(
            open(
              reader,
              (data, aad) => ctx.open(data, aad),
              maxChunkSize + suite.aead.tagSize,
            ),
            () => reader.close(),
          ),
          async encapsulateResponse(source) {
            if (used) throw new OhttpError("Response already encapsulated");
            used = true;
            const nonce = crypto.getRandomValues(
              new Uint8Array(
                Math.max(suite.aead.keySize, suite.aead.nonceSize),
              ),
            );
            const crypt = await responseCrypt(
              suite,
              enc,
              nonce,
              (label, n) => ctx.export(label, n),
              false,
            );
            const response = new ByteReader(source);
            return {
              body: stream(
                (async function* () {
                  yield nonce;
                  yield* seal(response, crypt);
                })(),
                () => response.close(),
              ),
              contentType: responseContentType,
            };
          },
        };
      } catch (error) {
        await reader.close();
        throw error;
      }
    },
  };
}
