// @ts-ignore: for "npm:"
// import * as kyber from "npm:crystals-kyber@5.1.0";

import type { KemInterface } from "../interfaces/kemInterface.ts";
import type { RecipientContextParams } from "../interfaces/recipientContextParams.ts";
import type { SenderContextParams } from "../interfaces/senderContextParams.ts";

import { INPUT_LENGTH_LIMIT } from "../consts.ts";
import {
  DecapError,
  DeriveKeyPairError,
  DeserializeError,
  EncapError,
  InvalidParamError,
  NotSupportedError,
  SerializeError,
} from "../errors.ts";
import { KemId } from "../identifiers.ts";
import { isCryptoKeyPair } from "../utils/misc.ts";
import { XCryptoKey } from "../xCryptoKey.ts";

import { Kyber768 } from "./pqkemPrimitives/kyber768.ts";

// import { INPUT_LENGTH_LIMIT } from "../consts.ts";

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
    // const keys = kyber.KeyGen768();
    // const sk = await this.deserializePrivateKey(new Uint8Array(keys[1]));
    // const pk = await this.deserializePublicKey(new Uint8Array(keys[0]));
    const keys = this._prim.generateKeyPair();
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
    const pkR = new Uint8Array(
      await this.serializePublicKey(params.recipientPublicKey),
    );
    try {
      // const res = kyber.Encrypt768(pkR);
      // return {
      //   sharedSecret: new Uint8Array(res[1]),
      //   enc: new Uint8Array(res[0]),
      // };
      const res = this._prim.encap(pkR);
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
      // const res = kyber.Decrypt768(new Uint8Array(params.enc), serializedSkR);
      // return new Uint8Array(res);
      return this._prim.decap(new Uint8Array(params.enc), serializedSkR);
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
