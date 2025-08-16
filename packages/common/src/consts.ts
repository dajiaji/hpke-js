// The input length limit (psk, psk_id, info, exporter_context, ikm).
export const INPUT_LENGTH_LIMIT = 8192;

export const INFO_LENGTH_LIMIT = 65536;

// The minimum length of a PSK.
export const MINIMUM_PSK_LENGTH = 32;

// b""
export const EMPTY: Uint8Array = /* @__PURE__ */ new Uint8Array(0);

// Common BigInt constants
export const N_0 = /* @__PURE__ */ BigInt(0);
export const N_1 = /* @__PURE__ */ BigInt(1);
export const N_2 = /* @__PURE__ */ BigInt(2);
export const N_7 = /* @__PURE__ */ BigInt(7);
export const N_32 = /* @__PURE__ */ BigInt(32);
export const N_256 = /* @__PURE__ */ BigInt(256);
export const N_0x71 = /* @__PURE__ */ BigInt(0x71);
