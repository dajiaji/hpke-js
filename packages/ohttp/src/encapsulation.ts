import type { CipherSuite } from "@hpke/core";

import { OhttpError } from "./errors.ts";

const REQUEST_INFO_LABEL = new TextEncoder().encode("message/bhttp request");
const RESPONSE_LABEL = new TextEncoder().encode("message/bhttp response");
const LABEL_KEY = new TextEncoder().encode("key");
const LABEL_NONCE = new TextEncoder().encode("nonce");

/**
 * Build the info parameter for HPKE SetupBase{S,R}.
 *
 * info = concat("message/bhttp request", 0x00, hdr)
 * hdr  = concat(keyId(1), kemId(2), kdfId(2), aeadId(2))
 */
function buildRequestInfo(hdr: Uint8Array): Uint8Array {
  const info = new Uint8Array(REQUEST_INFO_LABEL.length + 1 + hdr.length);
  info.set(REQUEST_INFO_LABEL, 0);
  info[REQUEST_INFO_LABEL.length] = 0;
  info.set(hdr, REQUEST_INFO_LABEL.length + 1);
  return info;
}

/**
 * Build the 7-byte header:
 *   keyId (1) || kemId (2) || kdfId (2) || aeadId (2)
 */
export function buildHeader(
  keyId: number,
  kemId: number,
  kdfId: number,
  aeadId: number,
): Uint8Array {
  const hdr = new Uint8Array(7);
  const view = new DataView(hdr.buffer);
  hdr[0] = keyId;
  view.setUint16(1, kemId);
  view.setUint16(3, kdfId);
  view.setUint16(5, aeadId);
  return hdr;
}

export interface EncapsulateRequestResult {
  encRequest: Uint8Array;
  context: RequestContext;
}

/** State retained by the client to decrypt the corresponding response. */
export interface RequestContext {
  enc: Uint8Array;
  suite: CipherSuite;
  senderExport: (
    exporterContext: ArrayBufferLike,
    len: number,
  ) => Promise<ArrayBuffer>;
}

/**
 * Encapsulate an OHTTP request (RFC 9458 Section 4.3).
 *
 * Returns the encrypted request and a context for decapsulating the response.
 */
export async function encapsulateRequest(
  suite: CipherSuite,
  keyId: number,
  kemId: number,
  kdfId: number,
  aeadId: number,
  recipientPublicKey: CryptoKey,
  binaryRequest: Uint8Array,
): Promise<EncapsulateRequestResult> {
  const hdr = buildHeader(keyId, kemId, kdfId, aeadId);
  const info = buildRequestInfo(hdr);

  const sctx = await suite.createSenderContext({
    recipientPublicKey,
    info: info.buffer as ArrayBuffer,
  });

  const enc = new Uint8Array(sctx.enc);
  const ct = new Uint8Array(
    await sctx.seal(binaryRequest, new Uint8Array(0)),
  );

  // hdr(7) + enc(Nenc) + ct(variable)
  const encRequest = new Uint8Array(hdr.length + enc.length + ct.length);
  encRequest.set(hdr, 0);
  encRequest.set(enc, hdr.length);
  encRequest.set(ct, hdr.length + enc.length);

  return {
    encRequest,
    context: {
      enc,
      suite,
      senderExport: (ctx, len) => sctx.export(ctx, len),
    },
  };
}

export interface DecapsulateRequestResult {
  binaryRequest: Uint8Array;
  context: ResponseContext;
}

/** State retained by the gateway to encrypt the response. */
export interface ResponseContext {
  enc: Uint8Array;
  suite: CipherSuite;
  recipientExport: (
    exporterContext: ArrayBufferLike,
    len: number,
  ) => Promise<ArrayBuffer>;
}

/**
 * Decapsulate an OHTTP request on the gateway side (RFC 9458 Section 4.3).
 */
export async function decapsulateRequest(
  suite: CipherSuite,
  recipientKey: CryptoKey,
  keyId: number,
  kemId: number,
  encRequest: Uint8Array,
): Promise<DecapsulateRequestResult> {
  const view = new DataView(
    encRequest.buffer,
    encRequest.byteOffset,
    encRequest.byteLength,
  );

  if (encRequest.byteLength < 7) {
    throw new OhttpError("Encapsulated request too short");
  }

  const reqKeyId = encRequest[0];
  const reqKemId = view.getUint16(1);
  const kdfId = view.getUint16(3);
  const aeadId = view.getUint16(5);

  if (reqKeyId !== keyId) {
    throw new OhttpError(
      `Key ID mismatch: expected ${keyId}, got ${reqKeyId}`,
    );
  }
  if (reqKemId !== kemId) {
    throw new OhttpError(
      `KEM ID mismatch: expected 0x${kemId.toString(16)}, got 0x${
        reqKemId.toString(16)
      }`,
    );
  }

  const nenc = suite.kem.encSize;
  const hdrLen = 7;

  if (encRequest.byteLength < hdrLen + nenc) {
    throw new OhttpError("Encapsulated request too short for enc");
  }

  const enc = encRequest.slice(hdrLen, hdrLen + nenc);
  const ct = encRequest.slice(hdrLen + nenc);

  const hdr = buildHeader(reqKeyId, reqKemId, kdfId, aeadId);
  const info = buildRequestInfo(hdr);

  const rctx = await suite.createRecipientContext({
    recipientKey,
    enc,
    info: info.buffer as ArrayBuffer,
  });

  const binaryRequest = new Uint8Array(
    await rctx.open(ct, new Uint8Array(0)),
  );

  return {
    binaryRequest,
    context: {
      enc,
      suite,
      recipientExport: (ctx, len) => rctx.export(ctx, len),
    },
  };
}

/**
 * Encapsulate an OHTTP response on the gateway side (RFC 9458 Section 4.4).
 *
 * Uses the HPKE exporter to derive response key/nonce.
 */
export async function encapsulateResponse(
  ctx: ResponseContext,
  binaryResponse: Uint8Array,
): Promise<Uint8Array> {
  const nn = ctx.suite.aead.nonceSize;
  const nk = ctx.suite.aead.keySize;
  const secretLen = Math.max(nn, nk);

  const secret = new Uint8Array(
    await ctx.recipientExport(
      RESPONSE_LABEL.buffer as ArrayBuffer,
      secretLen,
    ),
  );

  const responseNonce = new Uint8Array(secretLen);
  crypto.getRandomValues(responseNonce);

  const { key, nonce } = await deriveResponseKeyNonce(
    ctx.suite,
    ctx.enc,
    responseNonce,
    secret,
  );

  const aeadCtx = ctx.suite.aead.createEncryptionContext(key);
  const ct = new Uint8Array(
    await aeadCtx.seal(nonce, binaryResponse, new Uint8Array(0)),
  );

  const encResponse = new Uint8Array(responseNonce.length + ct.length);
  encResponse.set(responseNonce, 0);
  encResponse.set(ct, responseNonce.length);
  return encResponse;
}

/**
 * Decapsulate an OHTTP response on the client side (RFC 9458 Section 4.4).
 */
export async function decapsulateResponse(
  ctx: RequestContext,
  encResponse: Uint8Array,
): Promise<Uint8Array> {
  const nn = ctx.suite.aead.nonceSize;
  const nk = ctx.suite.aead.keySize;
  const secretLen = Math.max(nn, nk);

  if (encResponse.byteLength < secretLen) {
    throw new OhttpError("Encapsulated response too short");
  }

  const secret = new Uint8Array(
    await ctx.senderExport(
      RESPONSE_LABEL.buffer as ArrayBuffer,
      secretLen,
    ),
  );

  const responseNonce = encResponse.slice(0, secretLen);
  const ct = encResponse.slice(secretLen);

  const { key, nonce } = await deriveResponseKeyNonce(
    ctx.suite,
    ctx.enc,
    responseNonce,
    secret,
  );

  const aeadCtx = ctx.suite.aead.createEncryptionContext(key);
  return new Uint8Array(
    await aeadCtx.open(nonce, ct, new Uint8Array(0)),
  );
}

/**
 * Derive response AEAD key and nonce (RFC 9458 Section 4.4).
 *
 * salt = concat(enc, response_nonce)
 * prk  = Extract(salt, secret)
 * key  = Expand(prk, "key", Nk)
 * nonce = Expand(prk, "nonce", Nn)
 *
 * Uses raw HMAC for Extract because the salt length may exceed
 * the KDF's hashSize (which the HPKE KDF implementation rejects).
 */
async function deriveResponseKeyNonce(
  suite: CipherSuite,
  enc: Uint8Array,
  responseNonce: Uint8Array,
  secret: Uint8Array,
): Promise<{ key: ArrayBuffer; nonce: ArrayBuffer }> {
  const salt = new Uint8Array(enc.length + responseNonce.length);
  salt.set(enc, 0);
  salt.set(responseNonce, enc.length);

  // HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm)
  const hmacAlg = kdfHashAlgorithm(suite.kdf.id);
  const saltKey = await crypto.subtle.importKey(
    "raw",
    salt,
    { name: "HMAC", hash: hmacAlg },
    false,
    ["sign"],
  );
  const prk = await crypto.subtle.sign(
    "HMAC",
    saltKey,
    secret.buffer as ArrayBuffer,
  );

  const key = await suite.kdf.expand(prk, LABEL_KEY, suite.aead.keySize);
  const nonce = await suite.kdf.expand(
    prk,
    LABEL_NONCE,
    suite.aead.nonceSize,
  );

  return { key, nonce };
}

function kdfHashAlgorithm(kdfId: number): string {
  switch (kdfId) {
    case 0x0001:
      return "SHA-256";
    case 0x0002:
      return "SHA-384";
    case 0x0003:
      return "SHA-512";
    default:
      throw new OhttpError(`Unsupported KDF ID: 0x${kdfId.toString(16)}`);
  }
}
