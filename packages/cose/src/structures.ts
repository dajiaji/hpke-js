import { encode } from "./cbor/encoder.ts";
import type { CborValue } from "./cbor/types.ts";

/** COSE header label constants. */
export const HeaderLabel = {
  ALG: 1,
  KID: 4,
  IV: 5,
  EK: -4,
  PSK_ID: -5,
} as const;

/**
 * Build Enc_structure for Integrated Encryption (COSE_Encrypt0) AAD.
 *
 * Enc_structure = [
 *   "Encrypt0",            // context
 *   protected_header_bytes, // serialized protected header
 *   external_aad            // external additional authenticated data
 * ]
 */
export function buildEncStructure(
  protectedHeader: Uint8Array,
  externalAad: Uint8Array,
): Uint8Array {
  const structure: CborValue[] = [
    "Encrypt0",
    protectedHeader,
    externalAad,
  ];
  return encode(structure);
}

/**
 * Build Enc_structure for Key Encryption (COSE_Encrypt) AAD.
 *
 * Enc_structure = [
 *   "Encrypt",
 *   protected_header_bytes,
 *   external_aad
 * ]
 */
export function buildEncStructureEncrypt(
  protectedHeader: Uint8Array,
  externalAad: Uint8Array,
): Uint8Array {
  const structure: CborValue[] = [
    "Encrypt",
    protectedHeader,
    externalAad,
  ];
  return encode(structure);
}

/**
 * Build the HPKE info parameter for Key Encryption recipients
 * using the Recipient_structure.
 *
 * Recipient_structure = [
 *   "HPKE Recipient",             // context
 *   next_layer_alg,               // content encryption algorithm (e.g. 1 for A128GCM)
 *   recipient_protected_header,   // serialized recipient protected header
 *   recipient_extra_info          // additional info for key derivation
 * ]
 */
export function buildRecipientStructure(
  nextLayerAlg: number,
  recipientProtectedHeader: Uint8Array,
  recipientExtraInfo: Uint8Array,
): Uint8Array {
  const structure: CborValue[] = [
    "HPKE Recipient",
    nextLayerAlg,
    recipientProtectedHeader,
    recipientExtraInfo,
  ];
  return encode(structure);
}
