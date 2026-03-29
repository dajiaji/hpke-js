import type { KdfInterface } from "@hpke/common";

import { XCurveNativeDhkemPrimitives } from "./xCurveNative.ts";

// deno-fmt-ignore
const PKCS8_ALG_ID_X448 = new Uint8Array([
  0x30, 0x46, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6f, 0x04, 0x3a, 0x04, 0x38,
]);

const BASE_POINT_X448: Uint8Array = /* @__PURE__ */ (() => {
  const p = new Uint8Array(56);
  p[0] = 5;
  return p;
})();

export class X448 extends XCurveNativeDhkemPrimitives {
  constructor(hkdf: KdfInterface) {
    super("X448", 56, PKCS8_ALG_ID_X448, BASE_POINT_X448, hkdf);
  }
}
