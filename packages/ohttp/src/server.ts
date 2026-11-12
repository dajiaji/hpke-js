import { CipherSuite } from "@hpke/core";
import type { KemInterface } from "@hpke/common";

import { decodeRequest } from "./bhttp/decoder.ts";
import { encodeResponse } from "./bhttp/encoder.ts";
import { decapsulateRequest, encapsulateResponse } from "./encapsulation.ts";
import { OhttpError } from "./errors.ts";
import { serializeKeyConfig } from "./keyConfig.ts";
import { bindKdf, type OhttpSuite } from "./suite.ts";

const MEDIA_TYPE_REQUEST = "message/ohttp-req";
const MEDIA_TYPE_RESPONSE = "message/ohttp-res";
/** Problem type for key configuration errors (RFC 9458 Section 5.3). */
const PROBLEM_TYPE_KEY =
  "https://iana.org/assignments/http-problem-types#ohttp-key";

/** Parameters for {@link createOhttpServer}. */
export interface OhttpServerParams {
  /** Key identifier (0-255) advertised in the key configuration. */
  keyId: number;
  /** KEM primitive instance to use. */
  kem: KemInterface;
  /** KDF/AEAD pairs the gateway supports, in order of preference. */
  suites: OhttpSuite[];
  /** Existing key pair for `kem`. A new key pair is generated if omitted. */
  keyPair?: CryptoKeyPair;
}

/** Context returned by {@link OhttpServer.decapsulateRequest}. */
export interface OhttpServerContext {
  /** Decrypted target request. */
  readonly request: Request;
  /** Encrypts the response into an encapsulated response (`message/ohttp-res`). */
  encapsulateResponse(response: Response): Promise<Uint8Array>;
}

/**
 * OHTTP server, i.e. the Oblivious Gateway Resource (RFC 9458).
 *
 * Created with {@link createOhttpServer}.
 */
export interface OhttpServer {
  /** Serialized key configuration (`application/ohttp-keys`). */
  readonly keyConfig: Uint8Array;
  /**
   * Handles an HTTP request from the Oblivious Relay Resource.
   *
   * The encapsulated request is decrypted and passed to `handler`, and the
   * response returned by `handler` is encapsulated into a
   * `message/ohttp-res` response. This is the counterpart of
   * `OhttpClient.fetch()`.
   *
   * Requests that cannot be processed are answered with a 4xx response
   * without calling `handler`. Errors thrown by `handler` are propagated to
   * the caller.
   */
  handle(
    request: Request,
    handler: (request: Request) => Response | Promise<Response>,
  ): Promise<Response>;
  /**
   * Decapsulates an encapsulated request (`message/ohttp-req`), for manual
   * communication with the relay.
   */
  decapsulateRequest(
    encapsulatedRequest: Uint8Array,
  ): Promise<OhttpServerContext>;
}

class OhttpServerImpl implements OhttpServer {
  readonly keyConfig: Uint8Array;
  private _keyId: number;
  private _kemId: number;
  private _privateKey: CryptoKey;
  private _suites: CipherSuite[];

  constructor(
    keyId: number,
    kemId: number,
    privateKey: CryptoKey,
    suites: CipherSuite[],
    keyConfig: Uint8Array,
  ) {
    this._keyId = keyId;
    this._kemId = kemId;
    this._privateKey = privateKey;
    this._suites = suites;
    this.keyConfig = keyConfig;
  }

  async handle(
    request: Request,
    handler: (request: Request) => Response | Promise<Response>,
  ): Promise<Response> {
    if (request.method !== "POST") {
      return new Response(null, { status: 405, headers: { "Allow": "POST" } });
    }
    const mediaType = (request.headers.get("Content-Type") ?? "")
      .split(";")[0].trim().toLowerCase();
    if (mediaType !== MEDIA_TYPE_REQUEST) {
      return new Response(null, { status: 415 });
    }
    const encapsulatedRequest = new Uint8Array(await request.arrayBuffer());
    if (
      encapsulatedRequest.byteLength > 0 &&
      encapsulatedRequest[0] !== this._keyId
    ) {
      return new Response(
        JSON.stringify({
          type: PROBLEM_TYPE_KEY,
          title: "key identifier unknown",
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/problem+json" },
        },
      );
    }

    let ctx: OhttpServerContext;
    try {
      ctx = await this.decapsulateRequest(encapsulatedRequest);
    } catch {
      return new Response(null, { status: 400 });
    }

    const encapsulatedResponse = await ctx.encapsulateResponse(
      await handler(ctx.request),
    );
    return new Response(encapsulatedResponse.buffer as ArrayBuffer, {
      status: 200,
      headers: { "Content-Type": MEDIA_TYPE_RESPONSE },
    });
  }

  async decapsulateRequest(
    encapsulatedRequest: Uint8Array,
  ): Promise<OhttpServerContext> {
    if (encapsulatedRequest.byteLength < 7) {
      throw new OhttpError("Encapsulated request too short");
    }
    const view = new DataView(
      encapsulatedRequest.buffer,
      encapsulatedRequest.byteOffset,
      encapsulatedRequest.byteLength,
    );
    const kdfId = view.getUint16(3);
    const aeadId = view.getUint16(5);
    const suite = this._suites.find(
      (s) => s.kdf.id === kdfId && s.aead.id === aeadId,
    );
    if (!suite) {
      throw new OhttpError(
        `Unsupported cipher suite: KDF=0x${kdfId.toString(16)}, AEAD=0x${
          aeadId.toString(16)
        }`,
      );
    }

    const result = await decapsulateRequest(
      suite,
      this._privateKey,
      this._keyId,
      this._kemId,
      encapsulatedRequest,
    );
    const request = decodeRequest(result.binaryRequest);
    const respCtx = result.context;
    return {
      request,
      async encapsulateResponse(response: Response): Promise<Uint8Array> {
        return encapsulateResponse(respCtx, await encodeResponse(response));
      },
    };
  }
}

/**
 * Creates an OHTTP server, i.e. an Oblivious Gateway Resource (RFC 9458).
 *
 * A key pair is generated unless `keyPair` is given, and the key
 * configuration to be published is built up front.
 *
 * @throws {OhttpError} if the parameters are invalid.
 */
export async function createOhttpServer(
  params: OhttpServerParams,
): Promise<OhttpServer> {
  if (
    !Number.isInteger(params.keyId) || params.keyId < 0 || params.keyId > 255
  ) {
    throw new OhttpError(`Invalid keyId: ${params.keyId}`);
  }
  if (params.suites.length === 0) {
    throw new OhttpError("At least one KDF/AEAD pair is required");
  }
  // Each suite gets its own KDF state so that a KDF instance shared by
  // multiple suites (or with the caller) is not overwritten.
  const suites = params.suites.map((s) =>
    new CipherSuite({
      kem: params.kem,
      kdf: bindKdf(s.kdf),
      aead: s.aead,
    })
  );
  const kem = suites[0].kem;
  const keyPair = params.keyPair ?? await kem.generateKeyPair();

  const keyConfig = serializeKeyConfig({
    keyId: params.keyId,
    kem: kem.id,
    publicKey: new Uint8Array(await kem.serializePublicKey(keyPair.publicKey)),
    cipherSuites: params.suites.map((s) => ({
      kdf: s.kdf.id,
      aead: s.aead.id,
    })),
  });
  return new OhttpServerImpl(
    params.keyId,
    kem.id,
    keyPair.privateKey,
    suites,
    keyConfig,
  );
}
