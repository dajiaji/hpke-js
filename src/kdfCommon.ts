import { WebCrypto } from './webCrypto';

import * as consts from './consts';

export class KdfCommon extends WebCrypto {

  protected readonly suiteId: Uint8Array;
  protected readonly algHash: HmacKeyGenParams;
  protected readonly _nH: number;

  constructor(api: SubtleCrypto, suiteId: Uint8Array, algHash: HmacKeyGenParams) {
    if (algHash.length === undefined) {
      throw new Error('Unknown hash size');
    }
    super(api);
    this.suiteId = suiteId;
    this.algHash = algHash;
    this._nH = algHash.length / 8;
  }

  protected buildLabeledIkm(label: Uint8Array, ikm: Uint8Array): Uint8Array {
    const ret = new Uint8Array(7 + this.suiteId.byteLength + label.byteLength + ikm.byteLength);
    ret.set(consts.HPKE_VERSION, 0);
    ret.set(this.suiteId, 7);
    ret.set(label, 7 + this.suiteId.byteLength);
    ret.set(ikm, 7 + this.suiteId.byteLength + label.byteLength);
    return ret;
  }

  protected buildLabeledInfo(label: Uint8Array, info: Uint8Array, len: number): Uint8Array {
    const ret = new Uint8Array(9 + this.suiteId.byteLength + label.byteLength + info.byteLength);
    ret.set(new Uint8Array([0, len]), 0);
    ret.set(consts.HPKE_VERSION, 2);
    ret.set(this.suiteId, 9);
    ret.set(label, 9 + this.suiteId.byteLength);
    ret.set(info, 9 + this.suiteId.byteLength + label.byteLength);
    return ret;
  }

  protected async extract(salt: ArrayBuffer, ikm: ArrayBuffer): Promise<ArrayBuffer> {
    if (salt.byteLength === 0) {
      salt = new ArrayBuffer(this._nH);
    }
    const key = await this._api.importKey('raw', salt, this.algHash, false, ['sign']);
    return await this._api.sign('HMAC', key, ikm);
  }

  protected async expand(prk: ArrayBuffer, info: ArrayBuffer, len: number): Promise<ArrayBuffer> {
    const key = await this._api.importKey('raw', prk, this.algHash, false, ['sign']);

    const okm = new ArrayBuffer(len);
    const p = new Uint8Array(okm);
    let prev = consts.EMPTY;
    const mid = new Uint8Array(info);
    const tail = new Uint8Array(1);

    if (len > 255 * this._nH) {
      throw new Error('Entropy limit reached');
    }

    const tmp = new Uint8Array(this._nH + mid.length + 1);
    for (let i = 1, cur = 0; cur < p.length; i++) {
      tail[0] = i;
      tmp.set(prev, 0);
      tmp.set(mid, prev.length);
      tmp.set(tail, prev.length + mid.length);
      prev = new Uint8Array(await this._api.sign('HMAC', key, tmp.slice(0, prev.length + mid.length + 1)));
      if (p.length - cur >= prev.length) {
        p.set(prev, cur);
        cur += prev.length;
      } else {
        p.set(prev.slice(0, p.length - cur), cur);
        cur += p.length - cur;
      }
    }
    return okm;
  }

  protected async extractAndExpand(salt: ArrayBuffer, ikm: ArrayBuffer, info: ArrayBuffer, len: number): Promise<ArrayBuffer> {
    const baseKey = await this._api.importKey('raw', ikm, 'HKDF', false, consts.KEM_USAGES);
    return await this._api.deriveBits(
      {
        name: 'HKDF',
        hash: this.algHash.hash,
        salt: salt,
        info: info,
      },
      baseKey,
      len * 8,
    );
  }

  public async labeledExtract(salt: ArrayBuffer, label: Uint8Array, ikm: Uint8Array): Promise<ArrayBuffer> {
    return await this.extract(salt, this.buildLabeledIkm(label, ikm));
  }

  public async labeledExpand(prk: ArrayBuffer, label: Uint8Array, info: Uint8Array, len: number): Promise<ArrayBuffer> {
    return await this.expand(prk, this.buildLabeledInfo(label, info, len), len);
  }
}
