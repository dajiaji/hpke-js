const EMPTY = new Uint8Array(0);
const SEPARATOR = new Uint8Array([0xFF]);

/**
 * Build the HPKE info parameter for Key Encryption recipients
 * using the JOSE Recipient_structure.
 *
 * Recipient_structure = ASCII("JOSE-HPKE rcpt") ||
 *                       BYTE(255) ||
 *                       ASCII(content_encryption_alg) ||
 *                       BYTE(255) ||
 *                       recipient_extra_info
 *
 * See draft-ietf-jose-hpke-encrypt-16 Section 4.1.
 */
export function buildRecipientStructure(
  contentEncAlg: string,
  recipientExtraInfo: Uint8Array = EMPTY,
): Uint8Array {
  const te = new TextEncoder();
  const context = te.encode("JOSE-HPKE rcpt");
  const algBytes = te.encode(contentEncAlg);

  const result = new Uint8Array(
    context.length + 1 + algBytes.length + 1 + recipientExtraInfo.length,
  );
  let offset = 0;
  result.set(context, offset);
  offset += context.length;
  result.set(SEPARATOR, offset);
  offset += 1;
  result.set(algBytes, offset);
  offset += algBytes.length;
  result.set(SEPARATOR, offset);
  offset += 1;
  result.set(recipientExtraInfo, offset);

  return result;
}
