import type { KdfInterface } from "@hpke/common";

import { XCurveNativeDhkemPrimitives } from "./xCurveNative.ts";

// deno-fmt-ignore
const PKCS8_ALG_ID_X25519 = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

const BASE_POINT_X25519: Uint8Array = /* @__PURE__ */ (() => {
  const p = new Uint8Array(32);
  p[0] = 9;
  return p;
})();

export class X25519 extends XCurveNativeDhkemPrimitives {
  constructor(hkdf: KdfInterface) {
    super("X25519", 32, PKCS8_ALG_ID_X25519, BASE_POINT_X25519, hkdf);
  }
}
