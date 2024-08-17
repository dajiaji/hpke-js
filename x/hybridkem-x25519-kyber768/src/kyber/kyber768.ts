/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */
import { N } from "./consts.ts";
import { KyberBase } from "./kyberBase.ts";

/**
 * The Kyber768 implementation.
 *
 * @example
 *
 * ```ts
 * const recipient = new Kyber768();
 * const [pkR, skR] = await recipient.generateKeyPair();

 * const sender = new Kyber768();
 * const [ct, ssS] = await sender.encap(pkR);

 * const ssR = await recipient.decap(ct, skR);

 * console.assert(ssS === ssR, "The two shared secrets must match.");
 * ```
 */
export class Kyber768 extends KyberBase {
  protected _k = 3;
  protected _du = 10;
  protected _dv = 4;
  protected _eta1 = 2;
  protected _eta2 = 2;

  constructor() {
    super();
    this._skSize = 12 * this._k * N / 8;
    this._pkSize = this._skSize + 32;
    this._compressedUSize = this._k * this._du * N / 8;
    this._compressedVSize = this._dv * N / 8;
  }
}
