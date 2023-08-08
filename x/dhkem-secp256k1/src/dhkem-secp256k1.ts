// @ts-ignore: for "npm:"
import { secp256k1 } from "npm:@noble/curves@1.1.0/secp256k1";

import type { KemPrimitives } from "../../../src/interfaces/kemPrimitives.ts";
import type { KdfInterface } from "../../../src/interfaces/kdfInterface.ts";
import type { KemInterface } from "../../../src/interfaces/kemInterface.ts";

import { Algorithm } from "../../../src/algorithm.ts";
import { KemId } from "../../../src/identifiers.ts";
import {
  KEM_USAGES,
  LABEL_DKP_PRK,
  LABEL_SK,
} from "../../../src/interfaces/kemPrimitives.ts";
import { XCryptoKey } from "../../../src/xCryptoKey.ts";
import { HkdfSha256 } from "../../../src/kdfs/hkdfSha256.ts";
import { Dhkem } from "../../../src/kems/dhkem.ts";

import { EMPTY } from "../../../src/consts.ts";

const ALG_NAME = "ECDH";

class Secp256k1 extends Algorithm implements KemPrimitives {
  private _hkdf: KdfInterface;
  private _nPk: number;
  private _nSk: number;

  constructor(hkdf: KdfInterface) {
    super();
    this._hkdf = hkdf;
    this._nPk = 33;
    this._nSk = 32;
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    return await this._serializePublicKey(key as XCryptoKey);
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    return await this._deserializePublicKey(key);
  }

  public async importKey(
    format: "raw",
    key: ArrayBuffer,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    if (format !== "raw") {
      throw new Error("Unsupported format");
    }
    return await this._importKey(key, isPublic);
  }

  public async derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    return await this._derivePublicKey(key as XCryptoKey);
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    const rawSk = secp256k1.utils.randomPrivateKey();
    const sk = new XCryptoKey(ALG_NAME, rawSk, "private", KEM_USAGES);
    const pk = await this.derivePublicKey(sk);
    return { publicKey: pk, privateKey: sk };
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    const dkpPrk = await this._hkdf.labeledExtract(
      EMPTY,
      LABEL_DKP_PRK,
      new Uint8Array(ikm),
    );
    const rawSk = await this._hkdf.labeledExpand(
      dkpPrk,
      LABEL_SK,
      EMPTY,
      this._nSk,
    );
    const sk = new XCryptoKey(
      ALG_NAME,
      new Uint8Array(rawSk),
      "private",
      KEM_USAGES,
    );
    return {
      privateKey: sk,
      publicKey: await this.derivePublicKey(sk),
    };
  }

  public async dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    return await this._dh(sk as XCryptoKey, pk as XCryptoKey);
  }

  private _serializePublicKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve) => {
      resolve(k.key.buffer);
    });
  }

  private _deserializePublicKey(k: ArrayBuffer): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (k.byteLength !== this._nPk) {
        reject(new Error("Invalid public key for the ciphersuite"));
      } else {
        resolve(new XCryptoKey(ALG_NAME, new Uint8Array(k), "public"));
      }
    });
  }

  private _importKey(key: ArrayBuffer, isPublic: boolean): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (isPublic && key.byteLength !== this._nPk) {
        reject(new Error("Invalid public key for the ciphersuite"));
      }
      if (!isPublic && key.byteLength !== this._nSk) {
        reject(new Error("Invalid private key for the ciphersuite"));
      }
      resolve(
        new XCryptoKey(
          ALG_NAME,
          new Uint8Array(key),
          isPublic ? "public" : "private",
          isPublic ? [] : KEM_USAGES,
        ),
      );
    });
  }

  private _derivePublicKey(k: XCryptoKey): Promise<CryptoKey> {
    return new Promise((resolve) => {
      const pk = secp256k1.getPublicKey(k.key);
      resolve(new XCryptoKey(ALG_NAME, pk, "public"));
    });
  }

  private _dh(sk: XCryptoKey, pk: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      try {
        resolve(secp256k1.getSharedSecret(sk.key, pk.key).buffer);
      } catch (e: unknown) {
        reject(e);
      }
    });
  }
}

/**
 * The DHKEM(secp256k1, HKDF-SHA256).
 *
 * This class is implemented using
 * {@link https://github.com/paulmillr/noble-curves | @noble/curves}.
 *
 * The public keys are assumed to be compressed.
 *
 * The instance of this class can be specified to the
 * {@link https://deno.land/x/hpke/core/mod.ts?s=CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example
 * ```ts
 * import { KdfId, AeadId, CipherSuite } from "http://deno.land/x/hpke/core/mod.ts";
 * import { DhkemSecp256k1HkdfSha256} from "https://deno.land/x/hpke/x/dhkem-secp256k1/mod.ts";
 * const suite = new CipherSuite({
 *   kem: new DhkemSecp256k1HkdfSha256(),
 *   kdf: KdfId.HkdfSha256,
 *   aead: AeadId.Aes128Gcm,
 * });
 * ```
 *
 * @experimental Note that it is experimental and not standardized.
 */
export class DhkemSecp256k1HkdfSha256 extends Dhkem implements KemInterface {
  public readonly id: KemId = KemId.DhkemSecp256k1HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 33;
  public readonly publicKeySize: number = 33;
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    const prim = new Secp256k1(kdf);
    super(prim, kdf);
  }
}
