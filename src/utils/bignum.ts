/**
 * The minimum inplementation of bignum to derive an EC key pair.
 */
export class Bignum {

  private _num: Uint8Array;

  public constructor(size: number) {
    this._num = new Uint8Array(size);
  }

  public val(): Uint8Array {
    return this._num;
  }

  public reset() {
    this._num.fill(0);
  }

  public set(src: Uint8Array) {
    if (src.length !== this._num.length) {
      throw new Error('Bignum.set: invalid argument');
    }
    this._num.set(src);
  }

  public isZero(): boolean {
    for (let i = 0; i < this._num.length; i++) {
      if (this._num[i] !== 0) {
        return false;
      }
    }
    return true;
  }

  public lowerThan(v: Uint8Array): boolean {
    if (v.length !== this._num.length) {
      throw new Error('Bignum.lowerThan: invalid argument');
    }
    for (let i = 0; i < this._num.length; i++) {
      if (this._num[i] < v[i]) {
        return true;
      }
      if (this._num[i] > v[i]) {
        return false;
      }
    }
    return false;
  }
}
