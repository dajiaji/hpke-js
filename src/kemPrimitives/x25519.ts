import { generateKeyPair, scalarMultBase, sharedKey } from '@stablelib/x25519';

import type { KemPrimitives } from '../interfaces/kemPrimitives';
import type { KdfCommon } from '../kdfCommon';

import { Kem } from '../identifiers';
import { i2Osp } from '../utils/misc';

import * as consts from '../consts';

export class XCryptoKey implements CryptoKey {

  public readonly key: Uint8Array;
  public readonly type: 'public' | 'private';
  public readonly extractable: boolean = true;
  public readonly algorithm: KeyAlgorithm = { name: 'X25519' };
  public readonly usages: KeyUsage[] = consts.KEM_USAGES;

  constructor(key: Uint8Array, type: 'public' | 'private') {
    this.key = key;
    this.type = type;
  }
}

export class X25519 implements KemPrimitives {

  private _hkdf: KdfCommon;
  private _nPk: number;
  private _nSk: number;

  constructor(hkdf: KdfCommon) {
    this._hkdf = hkdf;
    this._nPk = 32;
    this._nSk = 32;
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    return await this._serializePublicKey(key as XCryptoKey);
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    return await this._deserializePublicKey(key);
  }

  public async derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    return await this._derivePublicKey(key as XCryptoKey);
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    return await this._generateKeyPair();
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    const dkpPrk = await this._hkdf.labeledExtract(consts.EMPTY, consts.LABEL_DKP_PRK, new Uint8Array(ikm));
    const rawSk = await this._hkdf.labeledExpand(dkpPrk, consts.LABEL_SK, consts.EMPTY, this._nSk);
    const sk = new XCryptoKey(new Uint8Array(rawSk), 'private');
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
        reject(new Error('invalid public key for the ciphersuite'));
      } else {
        resolve(new XCryptoKey(new Uint8Array(k), 'public'));
      }
    });
  }

  private _derivePublicKey(k: XCryptoKey): Promise<CryptoKey> {
    return new Promise((resolve) => {
      resolve(new XCryptoKey(scalarMultBase(k.key), 'public'));
    });
  }

  private _generateKeyPair(): Promise<CryptoKeyPair> {
    return new Promise((resolve) => {
      const kp = generateKeyPair();
      resolve({
        publicKey: new XCryptoKey(kp.publicKey, 'public'),
        privateKey: new XCryptoKey(kp.secretKey, 'private'),
      });
    });
  }

  private _dh(sk: XCryptoKey, pk: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      try {
        resolve(sharedKey(sk.key, pk.key));
      } catch (e: unknown) {
        reject(e);
      }
    });
  }
}
