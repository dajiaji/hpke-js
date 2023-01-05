import * as elliptic from "elliptic";

import type { KemPrimitives } from "../../interfaces/kemPrimitives.ts";
import type { KdfInterface } from "../../interfaces/kdfInterface.ts";

import { loadCrypto } from "../../webCrypto.ts";
import { XCryptoKey } from "../../xCryptoKey.ts";
import { bytesToHex, hexToBytes } from "../../utils/misc.ts";

import * as consts from "../../consts.ts";

const ALG_NAME = "ECDH";

export class Secp256K1 implements KemPrimitives {
  private _ec: elliptic.EC;
  private _hkdf: KdfInterface;
  private _nPk: number;
  private _nSk: number;

  constructor(hkdf: KdfInterface) {
    this._ec = new elliptic.EC("secp256k1");
    this._hkdf = hkdf;
    this._nPk = 65;
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
    const raw = new Uint8Array(32);
    const cryptoApi = await loadCrypto();
    cryptoApi.getRandomValues(raw);
    const sk = new XCryptoKey(ALG_NAME, raw, "private");
    const pk = await this.derivePublicKey(sk);
    return { publicKey: pk, privateKey: sk };
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    const dkpPrk = await this._hkdf.labeledExtract(
      consts.EMPTY,
      consts.LABEL_DKP_PRK,
      new Uint8Array(ikm),
    );
    const rawSk = await this._hkdf.labeledExpand(
      dkpPrk,
      consts.LABEL_SK,
      consts.EMPTY,
      this._nSk,
    );
    const sk = new XCryptoKey(ALG_NAME, new Uint8Array(rawSk), "private");
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
        ),
      );
    });
  }

  private _derivePublicKey(k: XCryptoKey): Promise<CryptoKey> {
    return new Promise((resolve) => {
      const kp = this._ec.keyFromPrivate(bytesToHex(k.key), "hex");
      resolve(
        new XCryptoKey(
          ALG_NAME,
          hexToBytes(kp.getPublic("hex")),
          "public",
        ),
      );
    });
  }

  private _dh(sk: XCryptoKey, pk: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      try {
        const skp = this._ec.keyFromPrivate(bytesToHex(sk.key), "hex");
        const rkp = this._ec.keyFromPublic(bytesToHex(pk.key), "hex");
        const ret = skp.derive(rkp.getPublic());
        resolve(hexToBytes(ret.toString(16, 2)));
      } catch (e: unknown) {
        reject(e);
      }
    });
  }
}
