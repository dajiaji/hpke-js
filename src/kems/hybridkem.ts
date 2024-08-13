import type { DhkemInterface } from "../../core/src/interfaces/dhkemInterface.ts";
import type { KdfInterface } from "../../core/src/interfaces/kdfInterface.ts";
import type { KemInterface } from "../../core/src/interfaces/kemInterface.ts";
import type { RecipientContextParams } from "../../core/src/interfaces/recipientContextParams.ts";
import type { SenderContextParams } from "../../core/src/interfaces/senderContextParams.ts";

import { EMPTY } from "../../core/src/consts.ts";
import {
  DeserializeError,
  InvalidParamError,
  NotSupportedError,
  SerializeError,
} from "../../core/src/errors.ts";
import { KemId } from "../../core/src/identifiers.ts";
import {
  LABEL_DKP_PRK,
  LABEL_SK,
} from "../../core/src/interfaces/dhkemPrimitives.ts";
import { SUITE_ID_HEADER_KEM } from "../../core/src/interfaces/kemInterface.ts";
import { concat, i2Osp, isCryptoKeyPair } from "../../core/src/utils/misc.ts";
import { XCryptoKey } from "../xCryptoKey.ts";

export class Hybridkem implements KemInterface {
  public readonly id: KemId = KemId.NotAssigned;
  public readonly name: string = "";
  public readonly secretSize: number = 0;
  public readonly encSize: number = 0;
  public readonly publicKeySize: number = 0;
  public readonly privateKeySize: number = 0;
  protected _a: DhkemInterface;
  protected _b: KemInterface;
  protected _kdf: KdfInterface;

  constructor(
    id: KemId,
    a: DhkemInterface,
    b: KemInterface,
    kdf: KdfInterface,
  ) {
    this.id = id;
    this._a = a;
    this._b = b;
    this._kdf = kdf;
    const suiteId = new Uint8Array(SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(this.id, 2), 3);
    this._kdf.init(suiteId);
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
    const kpA = await this._a.generateKeyPair();
    const kpB = await this._b.generateKeyPair();
    const pkA = await this._a.serializePublicKey(kpA.publicKey);
    const skA = await this._a.serializePrivateKey(kpA.privateKey);
    const pkB = await this._b.serializePublicKey(kpB.publicKey);
    const skB = await this._b.serializePrivateKey(kpB.privateKey);
    return {
      publicKey: await this.deserializePublicKey(
        concat(new Uint8Array(pkA), new Uint8Array(pkB)),
      ),
      privateKey: await this.deserializePrivateKey(
        concat(new Uint8Array(skA), new Uint8Array(skB)),
      ),
    };
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    const dkpPrk = await this._kdf.labeledExtract(
      EMPTY,
      LABEL_DKP_PRK,
      new Uint8Array(ikm),
    );
    const seed = new Uint8Array(
      await this._kdf.labeledExpand(
        dkpPrk,
        LABEL_SK,
        EMPTY,
        32 + 64,
      ),
    );
    const seed1 = seed.slice(0, 32);
    const seed2 = seed.slice(32, 96);
    const kpA = await this._a.deriveKeyPair(seed1);
    const kpB = await this._b.deriveKeyPair(seed2);
    const pkA = await this._a.serializePublicKey(kpA.publicKey);
    const skA = await this._a.serializePrivateKey(kpA.privateKey);
    const pkB = await this._b.serializePublicKey(kpB.publicKey);
    const skB = await this._b.serializePrivateKey(kpB.privateKey);
    return {
      publicKey: await this.deserializePublicKey(
        concat(new Uint8Array(pkA), new Uint8Array(pkB)),
      ),
      privateKey: await this.deserializePrivateKey(
        concat(new Uint8Array(skA), new Uint8Array(skB)),
      ),
    };
  }

  public async importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
    isPublic = true,
  ): Promise<CryptoKey> {
    if (format !== "raw") {
      throw new NotSupportedError("'jwk' is not supported");
    }
    if (!(key instanceof ArrayBuffer)) {
      throw new InvalidParamError("Invalid type of key");
    }
    if (isPublic) {
      return await this.deserializePublicKey(key as ArrayBuffer);
    }
    return await this.deserializePrivateKey(key as ArrayBuffer);
  }

  public async encap(
    params: SenderContextParams,
  ): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }> {
    let ekmA: ArrayBuffer | undefined = undefined;
    let ekmB: ArrayBuffer | undefined = undefined;
    if (params.ekm !== undefined && !isCryptoKeyPair(params.ekm)) {
      if (params.ekm.byteLength !== 64) {
        throw new InvalidParamError("ekm must be 64 bytes in length");
      }
      ekmA = params.ekm.slice(0, 32);
      ekmB = params.ekm.slice(32);
    }
    const pkR = new Uint8Array(
      await this.serializePublicKey(params.recipientPublicKey),
    );
    const pkRA = await this._a.deserializePublicKey(
      pkR.slice(0, this._a.publicKeySize),
    );
    const pkRB = await this._b.deserializePublicKey(
      pkR.slice(this._a.publicKeySize),
    );
    const resA = await this._a.encap({ recipientPublicKey: pkRA, ekm: ekmA });
    const resB = await this._b.encap({ recipientPublicKey: pkRB, ekm: ekmB });
    return {
      sharedSecret: concat(
        new Uint8Array(resA.sharedSecret),
        new Uint8Array(resB.sharedSecret),
      ),
      enc: concat(new Uint8Array(resA.enc), new Uint8Array(resB.enc)),
    };
  }

  public async decap(params: RecipientContextParams): Promise<ArrayBuffer> {
    const sk = isCryptoKeyPair(params.recipientKey)
      ? params.recipientKey.privateKey
      : params.recipientKey;
    const skR = new Uint8Array(await this.serializePrivateKey(sk));
    const skRA = await this._a.deserializePrivateKey(
      skR.slice(0, this._a.privateKeySize),
    );
    const skRB = await this._b.deserializePrivateKey(
      skR.slice(this._a.privateKeySize),
    );
    const ssA = await this._a.decap({
      recipientKey: skRA,
      enc: params.enc.slice(0, this._a.encSize),
    });
    const ssB = await this._b.decap({
      recipientKey: skRB,
      enc: params.enc.slice(this._a.encSize),
    });
    return concat(new Uint8Array(ssA), new Uint8Array(ssB));
  }

  private _serializePublicKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      if (k.type !== "public") {
        reject(new Error("Not public key"));
      }
      if (k.algorithm.name !== this.name) {
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
      resolve(new XCryptoKey(this.name, new Uint8Array(k), "public"));
    });
  }

  private _serializePrivateKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      if (k.type !== "private") {
        reject(new Error("Not private key"));
      }
      if (k.algorithm.name !== this.name) {
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
        new XCryptoKey(this.name, new Uint8Array(k), "private", ["deriveBits"]),
      );
    });
  }
}
