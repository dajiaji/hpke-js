import { BHttpDecoder, BHttpEncoder } from "@dajiaji/bhttp";
import { CipherSuite } from "@hpke/core";
import type { AeadInterface, KdfInterface, KemInterface } from "@hpke/common";

import type { OhttpKeyConfig } from "./keyConfig.ts";
import { serializeKeyConfig } from "./keyConfig.ts";
import { decapsulateRequest, encapsulateResponse } from "./encapsulation.ts";
import { OhttpError } from "./errors.ts";

/** A KDF/AEAD pair with concrete primitive instances. */
export interface KdfAeadPair {
  kdf: KdfInterface;
  aead: AeadInterface;
}

/** Configuration for constructing an OhttpServer with existing keys. */
export interface OhttpServerConfig {
  keyId: number;
  kem: KemInterface;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  kdfAeadPairs: KdfAeadPair[];
}

/** Parameters for OhttpServer.setup(). */
export interface OhttpServerSetupParams {
  keyId: number;
  kem: KemInterface;
  kdfAeadPairs: KdfAeadPair[];
}

/** Context returned after decapsulating a request. */
export interface OhttpServerContext {
  /** Decrypted target request. */
  readonly request: Request;
  /** Encrypt a response back to the client. */
  encapsulateResponse(response: Response): Promise<Uint8Array>;
}

/**
 * OHTTP Gateway / Server (RFC 9458).
 *
 * Decapsulates incoming OHTTP requests and encapsulates responses.
 */
export class OhttpServer {
  private _keyId: number;
  private _kem: KemInterface;
  private _privateKey: CryptoKey;
  private _publicKey: CryptoKey;
  private _kdfAeadPairs: KdfAeadPair[];
  private _publicKeyRaw: Uint8Array | undefined;
  private _publicKeyConfig: Uint8Array | undefined;

  constructor(config: OhttpServerConfig) {
    this._keyId = config.keyId;
    this._kem = config.kem;
    this._privateKey = config.privateKey;
    this._publicKey = config.publicKey;
    this._kdfAeadPairs = config.kdfAeadPairs;
  }

  /**
   * Generate a key pair and create an OhttpServer.
   */
  static async setup(params: OhttpServerSetupParams): Promise<OhttpServer> {
    if (params.kdfAeadPairs.length === 0) {
      throw new OhttpError("At least one KDF/AEAD pair is required");
    }

    const firstPair = params.kdfAeadPairs[0];
    const suite = new CipherSuite({
      kem: params.kem,
      kdf: firstPair.kdf,
      aead: firstPair.aead,
    });
    const keyPair = await suite.kem.generateKeyPair();

    return new OhttpServer({
      keyId: params.keyId,
      kem: params.kem,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      kdfAeadPairs: params.kdfAeadPairs,
    });
  }

  /**
   * Serialized public key configuration (`application/ohttp-keys`).
   */
  get publicKeyConfig(): Promise<Uint8Array> {
    return this._getPublicKeyConfig();
  }

  /**
   * Decapsulate an incoming OHTTP request.
   */
  async decapsulateRequest(
    encRequest: Uint8Array,
  ): Promise<OhttpServerContext> {
    if (encRequest.byteLength < 7) {
      throw new OhttpError("Encapsulated request too short");
    }

    const view = new DataView(
      encRequest.buffer,
      encRequest.byteOffset,
      encRequest.byteLength,
    );
    const kdfId = view.getUint16(3);
    const aeadId = view.getUint16(5);

    const pair = this._findKdfAeadPair(kdfId, aeadId);
    const suite = new CipherSuite({
      kem: this._kem,
      kdf: pair.kdf,
      aead: pair.aead,
    });

    const result = await decapsulateRequest(
      suite,
      this._privateKey,
      this._keyId,
      this._kem.id,
      encRequest,
    );

    const decoder = new BHttpDecoder();
    const request = decoder.decodeRequest(result.binaryRequest);
    const respCtx = result.context;

    return {
      request,
      async encapsulateResponse(response: Response): Promise<Uint8Array> {
        const encoder = new BHttpEncoder();
        const binaryResponse = await encoder.encodeResponse(response);
        return encapsulateResponse(respCtx, binaryResponse);
      },
    };
  }

  private async _getPublicKeyConfig(): Promise<Uint8Array> {
    if (this._publicKeyConfig) {
      return this._publicKeyConfig;
    }

    const rawKey = await this._getRawPublicKey();

    const config: OhttpKeyConfig = {
      keyId: this._keyId,
      kem: this._kem.id,
      publicKey: rawKey,
      cipherSuites: this._kdfAeadPairs.map((p) => ({
        kdf: p.kdf.id,
        aead: p.aead.id,
      })),
    };

    this._publicKeyConfig = serializeKeyConfig(config);
    return this._publicKeyConfig;
  }

  private async _getRawPublicKey(): Promise<Uint8Array> {
    if (this._publicKeyRaw) {
      return this._publicKeyRaw;
    }

    const firstPair = this._kdfAeadPairs[0];
    const suite = new CipherSuite({
      kem: this._kem,
      kdf: firstPair.kdf,
      aead: firstPair.aead,
    });
    const rawKey = new Uint8Array(
      await suite.kem.serializePublicKey(this._publicKey),
    );
    this._publicKeyRaw = rawKey;
    return rawKey;
  }

  private _findKdfAeadPair(kdfId: number, aeadId: number): KdfAeadPair {
    const pair = this._kdfAeadPairs.find(
      (p) => p.kdf.id === kdfId && p.aead.id === aeadId,
    );
    if (!pair) {
      throw new OhttpError(
        `Unsupported cipher suite: KDF=0x${kdfId.toString(16)}, AEAD=0x${
          aeadId.toString(16)
        }`,
      );
    }
    return pair;
  }
}
