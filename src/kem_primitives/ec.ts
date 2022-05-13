import type { KemPrimitives } from '../interfaces/kemPrimitives';
import type { KdfCommon } from '../kdfCommon';

import { Kem } from '../identifiers';

import { Bignum } from '../utils/bignum';
import { i2Osp } from '../utils/misc';

import * as consts from '../consts';
import * as errors from '../errors';

export class Ec implements KemPrimitives {

  private _kem: Kem;
  private _hkdf: KdfCommon;
  private _api: SubtleCrypto;
  private _alg: EcKeyGenParams;
  private _nPk: number;
  private _nSk: number;
  private _nDh: number;

  // EC specific arguments for deriving key pair.
  private _order: Uint8Array;
  private _sk: Bignum;
  private _bitmask: number;

  public constructor(kem: Kem, hkdf: KdfCommon, api: SubtleCrypto) {
    this._kem = kem;
    this._hkdf = hkdf;
    this._api = api;
    switch (this._kem) {
      case Kem.DhkemP256HkdfSha256:
        this._alg = { name: 'ECDH', namedCurve: 'P-256' };
        this._nPk = 65;
        this._nSk = 32;
        this._nDh = 32;
        this._order = consts.ORDER_P_256;
        this._bitmask = 0xFF;
        break;
      case Kem.DhkemP384HkdfSha384:
        this._alg = { name: 'ECDH', namedCurve: 'P-384' };
        this._nPk = 97;
        this._nSk = 48;
        this._nDh = 48;
        this._order = consts.ORDER_P_384;
        this._bitmask = 0xFF;
        break;
      default:
        // case Kem.DhkemP521HkdfSha512:
        this._alg = { name: 'ECDH', namedCurve: 'P-521' };
        this._nPk = 133;
        this._nSk = 66;
        this._nDh = 66;
        this._order = consts.ORDER_P_521;
        this._bitmask = 0x01;
        break;
    }
    this._sk = new Bignum(this._nSk);
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    const ret = await this._api.exportKey('raw', key);
    if (ret.byteLength !== this._nPk) {
      throw new errors.SerializeError('invalid public key length');
    }
    return ret;
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    if (key.byteLength !== this._nPk) {
      throw new errors.DeserializeError('invalid public key length');
    }
    try {
      return await this._api.importKey('raw', key, this._alg, true, []);
    } catch (e: unknown) {
      throw new errors.DeserializeError(e);
    }
  }

  public async derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    const jwk = await this._api.exportKey('jwk', key);
    delete jwk['d'];
    return await this._api.importKey('jwk', jwk, this._alg, true, ['deriveBits']);
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    return await this._api.generateKey(this._alg, true, consts.KEM_USAGES);
  }

  // TODO update to deriveKeyPair(ikm: ArrayBuffer) Promise<CryptoKeyPair>;
  public async deriveKey(ikm: ArrayBuffer): Promise<ArrayBuffer> {
    const dkpPrk = await this._hkdf.labeledExtract(consts.EMPTY, consts.LABEL_DKP_PRK, new Uint8Array(ikm));
    this._sk.reset();
    for (let counter = 0; this._sk.isZero() || !this._sk.lessThan(this._order); counter++) {
      if (counter > 255) {
        throw new errors.DeriveKeyPairError('faild to derive a key pair.');
      }
      const bytes = new Uint8Array(await this._hkdf.labeledExpand(dkpPrk, consts.LABEL_CANDIDATE, i2Osp(counter, 1), this._nSk));
      bytes[0] = bytes[0] & this._bitmask;
      this._sk.set(bytes);
    }
    return this._sk.val();
  }

  public async dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    const bits = await this._api.deriveBits(
      {
        name: 'ECDH',
        public: pk,
      },
      sk,
      this._nDh * 8,
    );
    return bits;
  }
}
