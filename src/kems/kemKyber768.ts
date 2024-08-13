// @ts-ignore: for "npm:"
// import * as kyber from "npm:crystals-kyber@5.1.0";

import type { KemInterface } from "../../core/src/interfaces/kemInterface.ts";
import type { RecipientContextParams } from "../../core/src/interfaces/recipientContextParams.ts";
import type { SenderContextParams } from "../../core/src/interfaces/senderContextParams.ts";

import { INPUT_LENGTH_LIMIT } from "../../core/src/consts.ts";
import {
  DecapError,
  DeriveKeyPairError,
  DeserializeError,
  EncapError,
  InvalidParamError,
  NotSupportedError,
  SerializeError,
} from "../../core/src/errors.ts";
import { KemId } from "../../core/src/identifiers.ts";
import { isCryptoKeyPair } from "../../core/src/utils/misc.ts";
import { XCryptoKey } from "../xCryptoKey.ts";

import { Kyber768 } from "./primitives/kyber/kyber768.ts";

const ALG_NAME = "Keyber768";

export class KemKyber768 implements KemInterface {
  public readonly id: KemId = KemId.NotAssigned;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 1088;
  public readonly publicKeySize: number = 1184;
  public readonly privateKeySize: number = 2400;
  private _prim: Kyber768;

  constructor() {
    this._prim = new Kyber768();
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._serializePublicKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    try {
      return await this._deserializePublicKey(key);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async serializePrivateKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._serializePrivateKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePrivateKey(key: ArrayBuffer): Promise<CryptoKey> {
    try {
      return await this._deserializePrivateKey(key);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    const keys = await this._prim.generateKeyPair();
    const sk = await this.deserializePrivateKey(keys[1]);
    const pk = await this.deserializePublicKey(keys[0]);
    return { publicKey: pk, privateKey: sk };
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    if (ikm.byteLength > INPUT_LENGTH_LIMIT) {
      throw new InvalidParamError("Too long ikm");
    }
    try {
      const keys = await this._prim.deriveKeyPair(new Uint8Array(ikm));
      const sk = await this.deserializePrivateKey(keys[1]);
      const pk = await this.deserializePublicKey(keys[0]);
      return { publicKey: pk, privateKey: sk };
    } catch (e: unknown) {
      throw new DeriveKeyPairError(e);
    }
  }

  public async importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
    isPublic = true,
  ): Promise<CryptoKey> {
    if (format !== "raw") {
      throw new NotSupportedError("'jwk' is not supported");
    }
    if (isPublic) {
      return await this.deserializePublicKey(key as ArrayBuffer);
    }
    return await this.deserializePrivateKey(key as ArrayBuffer);
  }

  public async encap(
    params: SenderContextParams,
  ): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }> {
    // params.ekm is only used for testing
    let ikm: Uint8Array | undefined = undefined;
    if (params.ekm !== undefined && !isCryptoKeyPair(params)) {
      if ((params.ekm as ArrayBuffer).byteLength !== 32) {
        throw new InvalidParamError("ekm must be 32 bytes in length");
      }
      ikm = new Uint8Array(params.ekm as ArrayBuffer);
    }
    const pkR = new Uint8Array(
      await this.serializePublicKey(params.recipientPublicKey),
    );
    try {
      const res = await this._prim.encap(pkR, ikm);
      return { sharedSecret: res[1], enc: res[0] };
    } catch (e: unknown) {
      throw new EncapError(e);
    }
  }

  public async decap(params: RecipientContextParams): Promise<ArrayBuffer> {
    const skR = isCryptoKeyPair(params.recipientKey)
      ? params.recipientKey.privateKey
      : params.recipientKey;
    const serializedSkR = new Uint8Array(await this.serializePrivateKey(skR));
    try {
      return await this._prim.decap(new Uint8Array(params.enc), serializedSkR);
    } catch (e: unknown) {
      throw new DecapError(e);
    }
  }

  private _serializePublicKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      if (k.type !== "public") {
        reject(new Error("Not public key"));
      }
      if (k.algorithm.name !== ALG_NAME) {
        reject(new Error(`Invalid algorithm name: ${k.algorithm.name}`));
      }
      if (k.key.byteLength !== this.publicKeySize) {
        reject(new Error(`Invalid key length: ${k.key.byteLength}`));
      }
      resolve(k.key.buffer);
    });
  }

  private _deserializePublicKey(k: ArrayBuffer): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (k.byteLength !== this.publicKeySize) {
        reject(new Error(`Invalid key length: ${k.byteLength}`));
      }
      resolve(new XCryptoKey(ALG_NAME, new Uint8Array(k), "public"));
    });
  }

  private _serializePrivateKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      if (k.type !== "private") {
        reject(new Error("Not private key"));
      }
      if (k.algorithm.name !== ALG_NAME) {
        reject(new Error(`Invalid algorithm name: ${k.algorithm.name}`));
      }
      if (k.key.byteLength !== this.privateKeySize) {
        reject(new Error(`Invalid key length: ${k.key.byteLength}`));
      }
      resolve(k.key.buffer);
    });
  }

  private _deserializePrivateKey(k: ArrayBuffer): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (k.byteLength !== this.privateKeySize) {
        reject(new Error(`Invalid key length: ${k.byteLength}`));
      }
      resolve(
        new XCryptoKey(ALG_NAME, new Uint8Array(k), "private", ["deriveBits"]),
      );
    });
  }
}
