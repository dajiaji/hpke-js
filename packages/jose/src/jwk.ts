import { decodeBase64Url } from "./utils.ts";
import type { JoseHpkeAlg } from "./alg.ts";
import { JoseError } from "./errors.ts";

/** Expected JWK key type and curve for a given JOSE HPKE algorithm. */
export function getExpectedJwkParams(
  alg: JoseHpkeAlg,
): { kty: string; crv: string } {
  switch (alg) {
    case "HPKE-0":
    case "HPKE-0-KE":
    case "HPKE-7":
    case "HPKE-7-KE":
      return { kty: "EC", crv: "P-256" };
    case "HPKE-1":
    case "HPKE-1-KE":
      return { kty: "EC", crv: "P-384" };
    case "HPKE-2":
    case "HPKE-2-KE":
      return { kty: "EC", crv: "P-521" };
    case "HPKE-3":
    case "HPKE-3-KE":
    case "HPKE-4":
    case "HPKE-4-KE":
      return { kty: "OKP", crv: "X25519" };
    case "HPKE-5":
    case "HPKE-5-KE":
    case "HPKE-6":
    case "HPKE-6-KE":
      return { kty: "OKP", crv: "X448" };
    default:
      throw new JoseError(`Unknown algorithm: ${alg}`);
  }
}

/**
 * Extract raw public key bytes from a JWK.
 * For EC keys: uncompressed point (0x04 || x || y).
 * For OKP keys: raw x coordinate bytes.
 */
export function extractPublicKeyBytesFromJwk(
  jwk: JsonWebKey,
  alg: JoseHpkeAlg,
): Uint8Array {
  const expected = getExpectedJwkParams(alg);
  if (jwk.kty !== expected.kty) {
    throw new JoseError(
      `JWK kty mismatch: expected ${expected.kty}, got ${jwk.kty}`,
    );
  }
  if (jwk.crv !== expected.crv) {
    throw new JoseError(
      `JWK crv mismatch: expected ${expected.crv}, got ${jwk.crv}`,
    );
  }

  if (!jwk.x) {
    throw new JoseError("JWK missing x parameter");
  }

  if (expected.kty === "EC") {
    if (!jwk.y) {
      throw new JoseError("JWK missing y parameter for EC key");
    }
    const x = decodeBase64Url(jwk.x);
    const y = decodeBase64Url(jwk.y);
    // Uncompressed point: 0x04 || x || y
    const raw = new Uint8Array(1 + x.length + y.length);
    raw[0] = 0x04;
    raw.set(x, 1);
    raw.set(y, 1 + x.length);
    return raw;
  }

  // OKP: raw x bytes
  return decodeBase64Url(jwk.x);
}

/**
 * Extract raw private key bytes from a JWK.
 * Returns the d parameter bytes.
 */
export function extractPrivateKeyBytesFromJwk(
  jwk: JsonWebKey,
  alg: JoseHpkeAlg,
): Uint8Array {
  const expected = getExpectedJwkParams(alg);
  if (jwk.kty !== expected.kty) {
    throw new JoseError(
      `JWK kty mismatch: expected ${expected.kty}, got ${jwk.kty}`,
    );
  }
  if (jwk.crv !== expected.crv) {
    throw new JoseError(
      `JWK crv mismatch: expected ${expected.crv}, got ${jwk.crv}`,
    );
  }

  if (!jwk.d) {
    throw new JoseError("JWK missing d parameter (private key)");
  }

  return decodeBase64Url(jwk.d);
}
