import { OhttpError } from "./errors.ts";

/** A KDF/AEAD pair advertised in a KeyConfig. */
export interface OhttpCipherSuite {
  kdf: number;
  aead: number;
}

/** Parsed public key configuration for OHTTP (RFC 9458 Section 3). */
export interface OhttpKeyConfig {
  keyId: number;
  kem: number;
  publicKey: Uint8Array;
  cipherSuites: OhttpCipherSuite[];
}

/**
 * Deserialize an `application/ohttp-keys` payload into key configurations.
 *
 * The wire format is a sequence of length-prefixed KeyConfig entries:
 *
 *   KeyConfig {
 *     Key Identifier (8),
 *     KEM ID (16),
 *     Public Key (Npk bytes, determined by KEM),
 *     Cipher Suites Length (16),
 *     Cipher Suites (variable) {
 *       KDF ID (16),
 *       AEAD ID (16),
 *     } ...
 *   }
 *
 * Each KeyConfig is prefixed with its 2-byte length.
 */
export function deserializeKeyConfig(data: Uint8Array): OhttpKeyConfig[] {
  const configs: OhttpKeyConfig[] = [];
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;

  while (offset < data.byteLength) {
    if (offset + 2 > data.byteLength) {
      throw new OhttpError("Truncated key configuration length prefix");
    }
    const configLen = view.getUint16(offset);
    offset += 2;

    if (offset + configLen > data.byteLength) {
      throw new OhttpError("Truncated key configuration entry");
    }

    const configEnd = offset + configLen;
    const config = parseSingleKeyConfig(data, view, offset, configEnd);
    configs.push(config);
    offset = configEnd;
  }

  return configs;
}

function parseSingleKeyConfig(
  data: Uint8Array,
  view: DataView,
  start: number,
  end: number,
): OhttpKeyConfig {
  let offset = start;

  if (offset + 1 > end) throw new OhttpError("Truncated key config: keyId");
  const keyId = data[offset];
  offset += 1;

  if (offset + 2 > end) throw new OhttpError("Truncated key config: kem");
  const kem = view.getUint16(offset);
  offset += 2;

  const npk = kemPublicKeyLength(kem);

  if (offset + npk > end) {
    throw new OhttpError("Truncated key config: publicKey");
  }
  const publicKey = data.slice(offset, offset + npk);
  offset += npk;

  if (offset + 2 > end) {
    throw new OhttpError("Truncated key config: cipherSuites length");
  }
  const csLen = view.getUint16(offset);
  offset += 2;

  if (csLen % 4 !== 0) {
    throw new OhttpError(
      "Invalid cipher suites length (must be multiple of 4)",
    );
  }
  if (offset + csLen > end) {
    throw new OhttpError("Truncated key config: cipherSuites");
  }

  const cipherSuites: OhttpCipherSuite[] = [];
  const csEnd = offset + csLen;
  while (offset < csEnd) {
    const kdf = view.getUint16(offset);
    offset += 2;
    const aead = view.getUint16(offset);
    offset += 2;
    cipherSuites.push({ kdf, aead });
  }

  return { keyId, kem, publicKey, cipherSuites };
}

/**
 * Serialize a single key configuration to `application/ohttp-keys` format.
 * The result is a length-prefixed KeyConfig entry.
 */
export function serializeKeyConfig(config: OhttpKeyConfig): Uint8Array {
  const npk = config.publicKey.byteLength;
  const csLen = config.cipherSuites.length * 4;
  // keyId(1) + kem(2) + publicKey(npk) + csLen(2) + cipherSuites(csLen)
  const configLen = 1 + 2 + npk + 2 + csLen;
  // 2-byte length prefix + config body
  const buf = new Uint8Array(2 + configLen);
  const view = new DataView(buf.buffer);
  let offset = 0;

  view.setUint16(offset, configLen);
  offset += 2;

  buf[offset] = config.keyId;
  offset += 1;

  view.setUint16(offset, config.kem);
  offset += 2;

  buf.set(config.publicKey, offset);
  offset += npk;

  view.setUint16(offset, csLen);
  offset += 2;

  for (const cs of config.cipherSuites) {
    view.setUint16(offset, cs.kdf);
    offset += 2;
    view.setUint16(offset, cs.aead);
    offset += 2;
  }

  return buf;
}

/** Return the public key length in bytes for a given KEM ID. */
function kemPublicKeyLength(kemId: number): number {
  switch (kemId) {
    case 0x0010: // DHKEM(P-256, HKDF-SHA256)
      return 65;
    case 0x0011: // DHKEM(P-384, HKDF-SHA384)
      return 97;
    case 0x0012: // DHKEM(P-521, HKDF-SHA512)
      return 133;
    case 0x0020: // DHKEM(X25519, HKDF-SHA256)
      return 32;
    case 0x0021: // DHKEM(X448, HKDF-SHA512)
      return 56;
    default:
      throw new OhttpError(`Unsupported KEM ID: 0x${kemId.toString(16)}`);
  }
}
