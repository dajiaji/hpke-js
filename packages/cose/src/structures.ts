import { encode } from "./cbor/encoder.ts";
import { CborTag, type CborValue } from "./cbor/types.ts";
import { CoseError } from "./errors.ts";

/** CBOR tags for COSE messages (RFC 9052 Section 2). */
export const CoseTag = {
  ENCRYPT0: 16,
  ENCRYPT: 96,
} as const;

/**
 * Find a header label present in both the protected and unprotected buckets.
 *
 * RFC 9052 Section 3 says applications SHOULD verify that a label does not
 * occur in both buckets; a message that is not rejected must take the
 * attribute from the protected bucket. This library chooses to reject such
 * messages as malformed.
 *
 * @returns The first duplicated label, or undefined if the buckets are disjoint.
 */
export function findDuplicateHeaderLabel(
  protectedMap: Map<CborValue, CborValue>,
  unprotectedMap: Map<CborValue, CborValue>,
): CborValue | undefined {
  for (const label of protectedMap.keys()) {
    if (unprotectedMap.has(label)) {
      return label;
    }
  }
  return undefined;
}

/**
 * Remove the optional COSE message tag from a decoded message.
 *
 * Per RFC 9052 Section 2, a COSE message is either untagged or carries the
 * tag of its own message type. Any other tag (including the tag of a
 * different COSE message type) is rejected rather than silently ignored.
 *
 * @throws {CoseError} if the value carries a tag other than expectedTag.
 */
export function untagCoseMessage(
  value: CborValue,
  expectedTag: number,
  name: string,
): CborValue {
  if (!(value instanceof CborTag)) {
    return value;
  }
  if (value.tag !== expectedTag) {
    throw new CoseError(
      `Unexpected CBOR tag ${value.tag} for ${name} (expected ${expectedTag})`,
    );
  }
  return value.value;
}

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
