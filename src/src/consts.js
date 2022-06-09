// The key usages for KEM.
export const KEM_USAGES = ["deriveBits"];
// The key usages for AEAD.
export const AEAD_USAGES = ["encrypt", "decrypt"];
// The input length limit (psk, psk_id, info, exporter_context, ikm).
export const INPUT_LENGTH_LIMIT = 128;
// The minimum length of a PSK.
export const MINIMUM_PSK_LENGTH = 32;
// b""
export const EMPTY = new Uint8Array(0);
// b"HPKE-v1"
export const HPKE_VERSION = new Uint8Array([72, 80, 75, 69, 45, 118, 49]);
// b"HPKE"
export const SUITE_ID_HEADER_HPKE = new Uint8Array([
    72,
    80,
    75,
    69,
    0,
    0,
    0,
    0,
    0,
    0,
]);
// b"KEM"
export const SUITE_ID_HEADER_KEM = new Uint8Array([75, 69, 77, 0, 0]);
// b"dkp_prk"
export const LABEL_DKP_PRK = new Uint8Array([100, 107, 112, 95, 112, 114, 107]);
// b"eae_prk"
export const LABEL_EAE_PRK = new Uint8Array([101, 97, 101, 95, 112, 114, 107]);
// b"info_hash"
export const LABEL_INFO_HASH = new Uint8Array([
    105,
    110,
    102,
    111,
    95,
    104,
    97,
    115,
    104,
]);
// b"psk_id_hash"
export const LABEL_PSK_ID_HASH = new Uint8Array([
    112,
    115,
    107,
    95,
    105,
    100,
    95,
    104,
    97,
    115,
    104,
]);
// b"secret"
export const LABEL_SECRET = new Uint8Array([115, 101, 99, 114, 101, 116]);
// b"shared_secret"
export const LABEL_SHARED_SECRET = new Uint8Array([
    115,
    104,
    97,
    114,
    101,
    100,
    95,
    115,
    101,
    99,
    114,
    101,
    116,
]);
// b"key"
export const LABEL_KEY = new Uint8Array([107, 101, 121]);
// b"base_nonce"
export const LABEL_BASE_NONCE = new Uint8Array([
    98,
    97,
    115,
    101,
    95,
    110,
    111,
    110,
    99,
    101,
]);
// b"exp"
export const LABEL_EXP = new Uint8Array([101, 120, 112]);
// b"sec"
export const LABEL_SEC = new Uint8Array([115, 101, 99]);
// b"candidate"
export const LABEL_CANDIDATE = new Uint8Array([
    99,
    97,
    110,
    100,
    105,
    100,
    97,
    116,
    101,
]);
// b"sk"
export const LABEL_SK = new Uint8Array([115, 107]);
// the order of the curve being used.
export const ORDER_P_256 = new Uint8Array([
    0xff,
    0xff,
    0xff,
    0xff,
    0x00,
    0x00,
    0x00,
    0x00,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xbc,
    0xe6,
    0xfa,
    0xad,
    0xa7,
    0x17,
    0x9e,
    0x84,
    0xf3,
    0xb9,
    0xca,
    0xc2,
    0xfc,
    0x63,
    0x25,
    0x51,
]);
export const ORDER_P_384 = new Uint8Array([
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xc7,
    0x63,
    0x4d,
    0x81,
    0xf4,
    0x37,
    0x2d,
    0xdf,
    0x58,
    0x1a,
    0x0d,
    0xb2,
    0x48,
    0xb0,
    0xa7,
    0x7a,
    0xec,
    0xec,
    0x19,
    0x6a,
    0xcc,
    0xc5,
    0x29,
    0x73,
]);
export const ORDER_P_521 = new Uint8Array([
    0x01,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xfa,
    0x51,
    0x86,
    0x87,
    0x83,
    0xbf,
    0x2f,
    0x96,
    0x6b,
    0x7f,
    0xcc,
    0x01,
    0x48,
    0xf7,
    0x09,
    0xa5,
    0xd0,
    0x3b,
    0xb5,
    0xc9,
    0xb8,
    0x89,
    0x9c,
    0x47,
    0xae,
    0xbb,
    0x6f,
    0xb7,
    0x1e,
    0x91,
    0x38,
    0x64,
    0x09,
]);
