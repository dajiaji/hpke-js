import { CipherSuite } from "@hpke/core";
import type { KemInterface } from "@hpke/common";

import { decodeResponse } from "./bhttp/decoder.ts";
import { encodeRequest } from "./bhttp/encoder.ts";
import { decapsulateResponse, encapsulateRequest } from "./encapsulation.ts";
import { OhttpError } from "./errors.ts";
import type { OhttpKeyConfig } from "./keyConfig.ts";
import { deserializeKeyConfig } from "./keyConfig.ts";
import { bindKdf, type OhttpSuite } from "./suite.ts";

/** Parameters for {@link createOhttpClient}. */
export interface OhttpClientParams {
  /** KEM primitive instance to use. */
  kem: KemInterface;
  /**
   * KDF/AEAD pairs the client supports. The first pair advertised by the
   * gateway's key configuration that is included here is used.
   */
  suites: OhttpSuite[];
  /**
   * Gateway's key configuration: raw `application/ohttp-keys` bytes or a
   * parsed configuration. When the raw bytes contain multiple
   * configurations, the first one the client supports is used.
   */
  keyConfig: Uint8Array | OhttpKeyConfig;
  /**
   * URL of the Oblivious Relay Resource. Required only for
   * {@link OhttpClient.fetch}.
   */
  relayUrl?: string | URL;
}

/** Context returned by {@link OhttpClient.encapsulateRequest}. */
export interface OhttpClientContext {
  /** Encapsulated request (`message/ohttp-req`). */
  readonly encapsulatedRequest: Uint8Array;
  /** Decrypts the corresponding encapsulated response (`message/ohttp-res`). */
  decapsulateResponse(encapsulatedResponse: Uint8Array): Promise<Response>;
}

/**
 * OHTTP client (RFC 9458).
 *
 * Created with {@link createOhttpClient}.
 */
export interface OhttpClient {
  /**
   * Sends an HTTP request through the Oblivious Relay Resource.
   *
   * The signature mirrors the standard `fetch()` API. Requires `relayUrl`.
   */
  fetch(input: Request | string | URL, init?: RequestInit): Promise<Response>;
  /**
   * Encapsulates a request without sending it, for manual communication
   * with the relay.
   */
  encapsulateRequest(request: Request): Promise<OhttpClientContext>;
}

class OhttpClientImpl implements OhttpClient {
  private _suite: CipherSuite;
  private _keyId: number;
  private _publicKey: CryptoKey;
  private _relayUrl: string | undefined;

  constructor(
    suite: CipherSuite,
    keyId: number,
    publicKey: CryptoKey,
    relayUrl: string | undefined,
  ) {
    this._suite = suite;
    this._keyId = keyId;
    this._publicKey = publicKey;
    this._relayUrl = relayUrl;
  }

  async fetch(
    input: Request | string | URL,
    init?: RequestInit,
  ): Promise<Response> {
    if (this._relayUrl === undefined) {
      throw new OhttpError("relayUrl is required to use fetch()");
    }
    const request = input instanceof Request
      ? (init ? new Request(input, init) : input)
      : new Request(input, init);

    const ctx = await this.encapsulateRequest(request);

    const relayResponse = await fetch(this._relayUrl, {
      method: "POST",
      headers: { "Content-Type": "message/ohttp-req" },
      body: ctx.encapsulatedRequest.slice().buffer as ArrayBuffer,
    });
    if (!relayResponse.ok) {
      throw new OhttpError(`Relay returned HTTP ${relayResponse.status}`);
    }

    return ctx.decapsulateResponse(
      new Uint8Array(await relayResponse.arrayBuffer()),
    );
  }

  async encapsulateRequest(request: Request): Promise<OhttpClientContext> {
    const result = await encapsulateRequest(
      this._suite,
      this._keyId,
      this._suite.kem.id,
      this._suite.kdf.id,
      this._suite.aead.id,
      this._publicKey,
      await encodeRequest(request),
    );
    const reqCtx = result.context;
    return {
      encapsulatedRequest: result.encRequest,
      async decapsulateResponse(
        encapsulatedResponse: Uint8Array,
      ): Promise<Response> {
        return decodeResponse(
          await decapsulateResponse(reqCtx, encapsulatedResponse),
        );
      },
    };
  }
}

/**
 * Selects the key configuration and KDF/AEAD pair to use. Key
 * configurations and their cipher suites are examined in the gateway's
 * order of preference (RFC 9458 Section 3.1).
 */
function selectKeyConfig(
  params: OhttpClientParams,
): { config: OhttpKeyConfig; suite: OhttpSuite } {
  const configs = params.keyConfig instanceof Uint8Array
    ? deserializeKeyConfig(params.keyConfig)
    : [params.keyConfig];
  if (configs.length === 0) {
    throw new OhttpError("Empty key configuration");
  }
  const kemId = params.kem.id;
  let kemMatched = false;
  for (const config of configs) {
    if (config.kem !== kemId) {
      continue;
    }
    kemMatched = true;
    for (const cs of config.cipherSuites) {
      const suite = params.suites.find(
        (s) => s.kdf.id === cs.kdf && s.aead.id === cs.aead,
      );
      if (suite) {
        return { config, suite };
      }
    }
  }
  if (!kemMatched) {
    throw new OhttpError(
      `KEM 0x${kemId.toString(16)} not found in key configuration`,
    );
  }
  throw new OhttpError(
    "No mutually supported KDF/AEAD pair in key configuration",
  );
}

/**
 * Creates an OHTTP client (RFC 9458).
 *
 * The gateway's key configuration is validated against the given
 * primitives and its public key is imported once, up front.
 *
 * @throws {OhttpError} if the key configuration is invalid or not supported
 *   by the given primitives.
 */
export async function createOhttpClient(
  params: OhttpClientParams,
): Promise<OhttpClient> {
  if (params.suites.length === 0) {
    throw new OhttpError("At least one KDF/AEAD pair is required");
  }
  const { config, suite: pair } = selectKeyConfig(params);
  const suite = new CipherSuite({
    kem: params.kem,
    // Keep the KDF state of this suite independent of the given instance.
    kdf: bindKdf(pair.kdf),
    aead: pair.aead,
  });

  let publicKey: CryptoKey;
  try {
    publicKey = await suite.kem.importKey(
      "raw",
      config.publicKey.slice().buffer as ArrayBuffer,
      true,
    );
  } catch (e: unknown) {
    throw new OhttpError(
      `Invalid public key in key configuration: ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
  }

  let relayUrl: string | undefined;
  if (params.relayUrl !== undefined) {
    try {
      relayUrl = new URL(params.relayUrl).toString();
    } catch {
      throw new OhttpError(`Invalid relayUrl: ${params.relayUrl}`);
    }
  }
  return new OhttpClientImpl(suite, config.keyId, publicKey, relayUrl);
}
