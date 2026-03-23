import { BHttpEncoder } from "@dajiaji/bhttp";
import { CipherSuite } from "@hpke/core";
import type { AeadInterface, KdfInterface, KemInterface } from "@hpke/common";

import type { OhttpCipherSuite, OhttpKeyConfig } from "./keyConfig.ts";
import { deserializeKeyConfig } from "./keyConfig.ts";
import {
  decapsulateResponse,
  encapsulateRequest,
  type RequestContext,
} from "./encapsulation.ts";
import { OhttpError } from "./errors.ts";

/** Parameters for constructing an OhttpClient. */
export interface OhttpClientParams {
  /** KEM primitive instance to use. */
  kem: KemInterface;
  /** KDF primitive instance to use. */
  kdf: KdfInterface;
  /** AEAD primitive instance to use. */
  aead: AeadInterface;
  /** Gateway's key configuration (raw `application/ohttp-keys` bytes or parsed). */
  keyConfig: Uint8Array | OhttpKeyConfig;
  /** URL of the Oblivious Relay Resource. */
  relayUrl: string | URL;
}

/** Context returned by encapsulateRequest for manual relay communication. */
export interface OhttpClientContext {
  /** Encrypted request payload (`message/ohttp-req`). */
  readonly encRequest: Uint8Array;
  /** Decrypt the relay's encapsulated response. */
  decapsulateResponse(encResponse: Uint8Array): Promise<Response>;
}

/**
 * OHTTP Client (RFC 9458).
 *
 * Provides a fetch-like API that transparently encrypts requests and
 * decrypts responses via an Oblivious Relay.
 */
export class OhttpClient {
  private _suite: CipherSuite;
  private _keyConfig: OhttpKeyConfig;
  private _relayUrl: URL;

  constructor(params: OhttpClientParams) {
    this._suite = new CipherSuite({
      kem: params.kem,
      kdf: params.kdf,
      aead: params.aead,
    });

    if (params.keyConfig instanceof Uint8Array) {
      const configs = deserializeKeyConfig(params.keyConfig);
      if (configs.length === 0) {
        throw new OhttpError("Empty key configuration");
      }
      this._keyConfig = configs[0];
    } else {
      this._keyConfig = params.keyConfig;
    }

    this._validateSuiteAgainstKeyConfig();
    this._relayUrl = new URL(params.relayUrl.toString());
  }

  /**
   * Send an HTTP request through the OHTTP relay.
   *
   * Signature mirrors the standard `fetch()` API.
   */
  async fetch(
    input: Request | string | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const request = input instanceof Request
      ? (init ? new Request(input, init) : input)
      : new Request(input, init);

    const ctx = await this.encapsulateRequest(request);

    const relayResponse = await fetch(this._relayUrl.toString(), {
      method: "POST",
      headers: { "Content-Type": "message/ohttp-req" },
      body: ctx.encRequest,
    });

    if (!relayResponse.ok) {
      throw new OhttpError(
        `Relay returned HTTP ${relayResponse.status}`,
      );
    }

    const encResponse = new Uint8Array(await relayResponse.arrayBuffer());
    return ctx.decapsulateResponse(encResponse);
  }

  /**
   * Low-level API: encapsulate a request for manual relay communication.
   */
  async encapsulateRequest(request: Request): Promise<OhttpClientContext> {
    const config = this._keyConfig;

    const publicKey = await this._suite.kem.importKey(
      "raw",
      config.publicKey.buffer as ArrayBuffer,
      true,
    );

    const encoder = new BHttpEncoder();
    const binaryRequest = await encoder.encodeRequest(request);

    const result = await encapsulateRequest(
      this._suite,
      config.keyId,
      config.kem,
      this._suite.kdf.id,
      this._suite.aead.id,
      publicKey,
      binaryRequest,
    );

    const reqCtx = result.context;

    return {
      encRequest: result.encRequest,
      decapsulateResponse(
        encResponse: Uint8Array,
      ): Promise<Response> {
        return decapResponse(reqCtx, encResponse);
      },
    };
  }

  private _validateSuiteAgainstKeyConfig(): void {
    const config = this._keyConfig;
    if (this._suite.kem.id !== config.kem) {
      throw new OhttpError(
        `KEM mismatch: suite has 0x${this._suite.kem.id.toString(16)}, ` +
          `key config has 0x${config.kem.toString(16)}`,
      );
    }
    const kdfId = this._suite.kdf.id;
    const aeadId = this._suite.aead.id;
    const found = config.cipherSuites.some(
      (cs: OhttpCipherSuite) => cs.kdf === kdfId && cs.aead === aeadId,
    );
    if (!found) {
      throw new OhttpError(
        `KDF/AEAD pair (0x${kdfId.toString(16)}, 0x${aeadId.toString(16)}) ` +
          `not found in key configuration`,
      );
    }
  }
}

async function decapResponse(
  reqCtx: RequestContext,
  encResponse: Uint8Array,
): Promise<Response> {
  const { BHttpDecoder } = await import("@dajiaji/bhttp");
  const binaryResponse = await decapsulateResponse(reqCtx, encResponse);
  const decoder = new BHttpDecoder();
  return decoder.decodeResponse(binaryResponse.buffer as ArrayBuffer);
}
