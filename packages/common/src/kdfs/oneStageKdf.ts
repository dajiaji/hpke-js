import type { KdfInterface } from "../interfaces/kdfInterface.ts";
import type { OneStageKdfInterface } from "../interfaces/oneStageKdfInterface.ts";

import { EMPTY } from "../consts.ts";
import { InvalidParamError, NotSupportedError } from "../errors.ts";
import type { KdfId } from "../identifiers.ts";
import { concat } from "../utils/misc.ts";
import { toUint8Array } from "./hkdf.ts";

// b"HPKE-v1"
// deno-fmt-ignore
const HPKE_VERSION = /* @__PURE__ */ new Uint8Array([
  72, 80, 75, 69, 45, 118, 49,
]);

// The maximum length that can be encoded as I2OSP(n, 2).
const MAX_UINT16 = 0xffff;

/**
 * Returns `I2OSP(len(x), 2) || x`.
 *
 * @throws {@link InvalidParamError} if `x` is longer than 65,535 bytes.
 */
export function lengthPrefixed(x: Uint8Array): Uint8Array {
  const len = x.byteLength;
  if (len > MAX_UINT16) {
    throw new InvalidParamError("Too long input to be length-prefixed");
  }
  const ret = new Uint8Array(2 + len);
  ret[0] = len >> 8;
  ret[1] = len;
  ret.set(x, 2);
  return ret;
}

/**
 * Builds the input of `Derive()` for `LabeledDerive()`, that is,
 * `ikm || "HPKE-v1" || suite_id || lengthPrefixed(label) || I2OSP(L, 2) || context`.
 *
 * @param suiteId A `suite_id` of a KEM or an HPKE ciphersuite.
 * @param ikm An input keying material.
 * @param label A byte string indicating the cryptographic context/operation.
 * @param context An additional byte string.
 * @param len The length in bytes of the output keying material (L).
 * @throws {@link InvalidParamError} if `label` or `len` is too large.
 */
export function buildLabeledDeriveIkm(
  suiteId: Uint8Array,
  ikm: Uint8Array,
  label: Uint8Array,
  context: Uint8Array,
  len: number,
): Uint8Array {
  if (!Number.isInteger(len) || len < 0 || len > MAX_UINT16) {
    throw new InvalidParamError("Invalid length of the output");
  }
  return concat(
    ikm,
    HPKE_VERSION,
    suiteId,
    lengthPrefixed(label),
    // I2OSP(len, 2)
    new Uint8Array([len >> 8, len]),
    context,
  );
}

/**
 * Checks whether the KDF is a one-stage KDF.
 */
export function isOneStageKdf(kdf: KdfInterface): kdf is OneStageKdfInterface {
  return typeof (kdf as Partial<OneStageKdfInterface>).labeledDerive ===
    "function";
}

/**
 * The base class of one-stage KDFs.
 *
 * Subclasses only have to provide `id`, `hashSize` and `_derive()`.
 */
export abstract class OneStageKdf implements OneStageKdfInterface {
  public abstract readonly id: KdfId;
  public abstract readonly hashSize: number;
  protected _suiteId: Uint8Array = EMPTY;

  /**
   * The underlying XOF.
   *
   * @param ikm An input keying material.
   * @param len The length in bytes of the output keying material.
   */
  protected abstract _derive(ikm: Uint8Array, len: number): Uint8Array;

  public init(suiteId: Uint8Array): void {
    this._suiteId = suiteId;
  }

  public derive(
    ikm: ArrayBufferLike | ArrayBufferView,
    len: number,
  ): Promise<ArrayBuffer> {
    try {
      if (!Number.isInteger(len) || len < 0 || len > MAX_UINT16) {
        throw new InvalidParamError("Invalid length of the output");
      }
      return Promise.resolve(
        this._derive(toUint8Array(ikm), len).buffer as ArrayBuffer,
      );
    } catch (e: unknown) {
      return Promise.reject(e);
    }
  }

  public labeledDerive(
    ikm: ArrayBufferLike | ArrayBufferView,
    label: Uint8Array,
    context: Uint8Array,
    len: number,
  ): Promise<ArrayBuffer> {
    try {
      if (this._suiteId === EMPTY) {
        throw new Error("Not initialized. Call init()");
      }
      const labeledIkm = buildLabeledDeriveIkm(
        this._suiteId,
        toUint8Array(ikm),
        label,
        context,
        len,
      );
      return Promise.resolve(
        this._derive(labeledIkm, len).buffer as ArrayBuffer,
      );
    } catch (e: unknown) {
      return Promise.reject(e);
    }
  }

  public buildLabeledIkm(_label: Uint8Array, _ikm: Uint8Array): Uint8Array {
    throw new NotSupportedError("Not supported by one-stage KDFs");
  }

  public buildLabeledInfo(
    _label: Uint8Array,
    _info: Uint8Array,
    _len: number,
  ): Uint8Array {
    throw new NotSupportedError("Not supported by one-stage KDFs");
  }

  public extract(
    _salt: ArrayBufferLike | ArrayBufferView,
    _ikm: ArrayBufferLike | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    return notSupported();
  }

  public expand(
    _prk: ArrayBufferLike | ArrayBufferView,
    _info: ArrayBufferLike | ArrayBufferView,
    _len: number,
  ): Promise<ArrayBuffer> {
    return notSupported();
  }

  public extractAndExpand(
    _salt: ArrayBufferLike | ArrayBufferView,
    _ikm: ArrayBufferLike | ArrayBufferView,
    _info: ArrayBufferLike | ArrayBufferView,
    _len: number,
  ): Promise<ArrayBuffer> {
    return notSupported();
  }

  public labeledExtract(
    _salt: ArrayBufferLike | ArrayBufferView,
    _label: Uint8Array,
    _ikm: Uint8Array,
  ): Promise<ArrayBuffer> {
    return notSupported();
  }

  public labeledExpand(
    _prk: ArrayBufferLike | ArrayBufferView,
    _label: Uint8Array,
    _info: Uint8Array,
    _len: number,
  ): Promise<ArrayBuffer> {
    return notSupported();
  }
}

function notSupported(): Promise<ArrayBuffer> {
  return Promise.reject(
    new NotSupportedError("Not supported by one-stage KDFs"),
  );
}
