import type { CipherSuite } from "@hpke/core";
import type { OhttpSource } from "./streams.ts";

/** Client-side binary HTTP exchange. Streams must be consumed exactly once. */
export interface OhttpClientContext {
  readonly body: ReadableStream<Uint8Array>;
  readonly contentType: string;
  decapsulateResponse(source: OhttpSource): Promise<ReadableStream<Uint8Array>>;
}

/** Gateway-side binary HTTP exchange. EOF establishes authenticated completion. */
export interface OhttpGatewayContext {
  readonly body: ReadableStream<Uint8Array>;
  encapsulateResponse(source: OhttpSource): Promise<{
    body: ReadableStream<Uint8Array>;
    contentType: string;
  }>;
}

/** Injected wire encoding; implementations must not select cryptographic primitives. */
export interface OhttpEncoding {
  readonly requestContentType: string;
  readonly responseContentType: string;
  /** Whether this encoding supports incremental encryption and decryption. */
  readonly incremental: boolean;
  encapsulateRequest(
    suite: CipherSuite,
    keyId: number,
    key: CryptoKey,
    source: OhttpSource,
  ): Promise<OhttpClientContext>;
  decapsulateRequest(
    suite: CipherSuite,
    keyId: number,
    key: CryptoKey,
    source: OhttpSource,
  ): Promise<OhttpGatewayContext>;
}
