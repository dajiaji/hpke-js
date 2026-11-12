import { CipherSuite } from "@hpke/core";
import type { AeadInterface, KdfInterface, KemInterface } from "@hpke/common";
import {
  deserializeKeyConfig,
  type OhttpKeyConfig,
  validateKeyId,
} from "./keyConfig.ts";
import type { OhttpClientContext, OhttpEncoding } from "./encoding.ts";
import type { OhttpSource } from "./streams.ts";
import { bindKdf } from "./suite.ts";
import { OhttpError } from "./errors.ts";

/** Explicit primitives and wire encoding for an OHTTP client. */
export interface OhttpClientParams {
  /** KEM primitive supplied by the application. */
  kem: KemInterface;
  /** KDF primitive supplied by the application. */
  kdf: KdfInterface;
  /** AEAD primitive supplied by the application. */
  aead: AeadInterface;
  /** Gateway key configurations as application/ohttp-keys bytes, or one parsed configuration. */
  keyConfig: Uint8Array | OhttpKeyConfig;
  /** Wire encoding supported by the gateway. */
  encoding: OhttpEncoding;
  /** Required by ohttpFetch; optional for low-level use. */
  relayUrl?: string | URL;
  /** Opt into streaming relay uploads. Defaults to false for HTTP/1.1/browser compatibility.
   * Decrypted responses still stream when the encoding supports it.
   */
  streamingUpload?: boolean;
}

/** Binary HTTP client. HTTP conversion and transport live in @hpke/ohttp/http. */
export interface OhttpClient {
  readonly relayUrl: string | undefined;
  readonly encoding: OhttpEncoding;
  readonly streamingUpload: boolean;
  encapsulateRequest(source: OhttpSource): Promise<OhttpClientContext>;
}

/** Create a client without importing any concrete wire encoding or HTTP adapter. */
export function createOhttpClient(params: OhttpClientParams): OhttpClient {
  const suite = new CipherSuite({ ...params, kdf: bindKdf(params.kdf) });
  const configs = params.keyConfig instanceof Uint8Array
    ? deserializeKeyConfig(params.keyConfig)
    : [params.keyConfig];
  if (!configs.length) throw new OhttpError("Empty key configuration");
  const matchingKem = configs.filter((config) => config.kem === suite.kem.id);
  if (!matchingKem.length) throw new OhttpError("KEM mismatch");
  const config = matchingKem.find((config) =>
    config.cipherSuites.some(
      (pair) => pair.kdf === suite.kdf.id && pair.aead === suite.aead.id,
    )
  );
  if (!config) {
    throw new OhttpError("KDF/AEAD pair not found in key configuration");
  }
  validateKeyId(config.keyId);
  const publicKeyBytes = config.publicKey.slice();
  const keyId = config.keyId;
  const encoding = params.encoding;
  const relayUrl = params.relayUrl === undefined
    ? undefined
    : new URL(params.relayUrl).href;
  return {
    relayUrl,
    encoding,
    streamingUpload: params.streamingUpload ?? false,
    async encapsulateRequest(source) {
      const key = await suite.kem.importKey("raw", publicKeyBytes.buffer, true);
      return encoding.encapsulateRequest(suite, keyId, key, source);
    },
  };
}
