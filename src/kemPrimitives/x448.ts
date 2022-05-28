import { getPublicKey, getSharedSecret } from 'x448-js';

import type { KemPrimitives } from '../interfaces/kemPrimitives';
import type { KdfCommon } from '../kdfCommon';

import { loadCrypto } from '../webCrypto';
import { XCryptoKey } from '../xCryptoKey';

import * as consts from '../consts';

const ALG_NAME = 'X448';

export class X448 implements KemPrimitives {

  private _hkdf: KdfCommon;
  private _nPk: number;
  private _nSk: number;

  constructor(hkdf: KdfCommon) {
    this._hkdf = hkdf;
    this._nPk = 56;
    this._nSk = 56;
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    return await this._serializePublicKey(key as XCryptoKey);
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    return await this._deserializePublicKey(key);
  }

  public async importKey(format: 'raw', key: ArrayBuffer, isPublic: boolean): Promise<CryptoKey> {
    if (format !== 'raw') {
      throw new Error('Unsupported format');
    }
    return await this._importKey(key, isPublic);
  }

  public async derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    return await this._derivePublicKey(key as XCryptoKey);
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    const sk = new Uint8Array(56);
    const cryptoApi = await loadCrypto();
    cryptoApi.getRandomValues(sk);
    return await this.deriveKeyPair(sk);
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    const dkpPrk = await this._hkdf.labeledExtract(consts.EMPTY, consts.LABEL_DKP_PRK, new Uint8Array(ikm));
    const rawSk = await this._hkdf.labeledExpand(dkpPrk, consts.LABEL_SK, consts.EMPTY, this._nSk);
    const sk = new XCryptoKey(ALG_NAME, new Uint8Array(rawSk), 'private');
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
        reject(new Error('Invalid public key for the ciphersuite'));
      } else {
        resolve(new XCryptoKey(ALG_NAME, new Uint8Array(k), 'public'));
      }
    });
  }

  private _importKey(key: ArrayBuffer, isPublic: boolean): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (isPublic && key.byteLength !== this._nPk) {
        reject(new Error('Invalid public key for the ciphersuite'));
      }
      if (!isPublic && key.byteLength !== this._nSk) {
        reject(new Error('Invalid private key for the ciphersuite'));
      }
      resolve(new XCryptoKey(ALG_NAME, new Uint8Array(key), isPublic ? 'public' : 'private'));
    });
  }

  private _derivePublicKey(k: XCryptoKey): Promise<CryptoKey> {
    return new Promise((resolve) => {
      resolve(new XCryptoKey(ALG_NAME, Uint8Array.from(getPublicKey(k.key)), 'public'));
    });
  }

  private _dh(sk: XCryptoKey, pk: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      try {
        resolve(Uint8Array.from(getSharedSecret(sk.key, pk.key)));
      } catch (e: unknown) {
        reject(e);
      }
    });
  }
}
