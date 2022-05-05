// The key usages for KEM.
export const KEM_USAGES: KeyUsage[] = ['deriveKey', 'deriveBits'];
// The key usages for AEAD.
export const AEAD_USAGES: KeyUsage[] = ['encrypt', 'decrypt'];

// b""
export const EMPTY = new Uint8Array(0);
// b"HPKE-v1"
export const HPKE_VERSION = new Uint8Array([72, 80, 75, 69, 45, 118, 49]);
// b"HPKE"
export const SUITE_ID_HEADER_HPKE = new Uint8Array([72, 80, 75, 69]);
// b"KEM"
export const SUITE_ID_HEADER_KEM = new Uint8Array([75, 69, 77]);
// b"dkp_prk"
export const LABEL_DKP_PRK = new Uint8Array([100, 107, 112, 95, 112, 114, 107]);
// b"eae_prk"
export const LABEL_EAE_PRK = new Uint8Array([101, 97, 101, 95, 112, 114, 107]);
// b"info_hash"
export const LABEL_INFO_HASH = new Uint8Array([105, 110, 102, 111, 95, 104, 97, 115, 104]);
// b"psk_id_hash"
export const LABEL_PSK_ID_HASH = new Uint8Array([112, 115, 107, 95, 105, 100, 95, 104, 97, 115, 104]);
// b"secret"
export const LABEL_SECRET = new Uint8Array([115, 101, 99, 114, 101, 116]);
// b"shared_secret"
export const LABEL_SHARED_SECRET = new Uint8Array([115, 104, 97, 114, 101, 100, 95, 115, 101,99, 114, 101, 116]);
// b"key"
export const LABEL_KEY = new Uint8Array([107, 101, 121]);
// b"base_nonce"
export const LABEL_BASE_NONCE = new Uint8Array([98, 97, 115, 101, 95, 110, 111, 110, 99, 101]);
// b"exp"
export const LABEL_EXP = new Uint8Array([101, 120, 112]);
// b"sec"
export const LABEL_SEC = new Uint8Array([115, 101, 99]);
// b"candidate"
export const LABEL_CANDIDATE = new Uint8Array([ 99, 97, 110, 100, 105, 100, 97, 116, 101]);
// b"sk"
export const LABEL_SK = new Uint8Array([115, 107]);
