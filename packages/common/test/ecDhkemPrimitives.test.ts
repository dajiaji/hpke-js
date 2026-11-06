import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  EC_P_256,
  EC_P_384,
  EC_P_521,
  type EcCurve,
  EcDhkemPrimitives,
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
  type KdfInterface,
} from "../mod.ts";

// suite_id = concat("KEM", I2OSP(kem_id, 2))
function kemKdf(kdf: KdfInterface, kemId: number): () => KdfInterface {
  return () => {
    kdf.init(new Uint8Array([75, 69, 77, kemId >> 8, kemId & 0xff]));
    return kdf;
  };
}

const CURVES: [EcCurve, () => KdfInterface][] = [
  [EC_P_256, kemKdf(new HkdfSha256Native(), 0x0010)],
  [EC_P_384, kemKdf(new HkdfSha384Native(), 0x0011)],
  [EC_P_521, kemKdf(new HkdfSha512Native(), 0x0012)],
];

const hex = (s: string) =>
  new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));

// Exposes the private fallback used when JWK export fails (Firefox).
interface EcWithFallback {
  _derivePublicKeyWithoutJwkExport(key: CryptoKey): Promise<CryptoKey>;
}

describe("EcDhkemPrimitives", () => {
  it("P-256 deriveKeyPair should match RFC 9180 A.3.1 (skEm/pkEm)", async () => {
    const ec = new EcDhkemPrimitives(EC_P_256, CURVES[0][1]());
    const kp = await ec.deriveKeyPair(
      hex("4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e"),
    );
    assertEquals(
      new Uint8Array(await ec.serializePrivateKey(kp.privateKey)),
      hex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"),
    );
    assertEquals(
      new Uint8Array(await ec.serializePublicKey(kp.publicKey)),
      hex(
        "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
      ),
    );
  });

  for (const [curve, kdf] of CURVES) {
    describe(curve.namedCurve, () => {
      it("deriveKeyPair should be deterministic and yield a valid key pair", async () => {
        const ec = new EcDhkemPrimitives(curve, kdf());
        const ikm = new Uint8Array(32).fill(1);
        const kp1 = await ec.deriveKeyPair(ikm);
        const kp2 = await ec.deriveKeyPair(ikm);
        const sk1 = new Uint8Array(
          await ec.serializePrivateKey(kp1.privateKey),
        );
        const sk2 = new Uint8Array(
          await ec.serializePrivateKey(kp2.privateKey),
        );
        assertEquals(sk1.length, curve.size);
        assertEquals(sk1, sk2);
        const pk = new Uint8Array(await ec.serializePublicKey(kp1.publicKey));
        assertEquals(pk.length, 1 + curve.size * 2);
        assertEquals(
          pk,
          new Uint8Array(
            await ec.serializePublicKey(
              await ec.derivePublicKey(kp1.privateKey),
            ),
          ),
        );
      });

      it("derivePublicKey fallback should recover the public key up to sign", async () => {
        const ec = new EcDhkemPrimitives(curve, kdf());
        const kp = await ec.generateKeyPair();
        const expected = new Uint8Array(
          await ec.serializePublicKey(kp.publicKey),
        );
        const derived = await (ec as unknown as EcWithFallback)
          ._derivePublicKeyWithoutJwkExport(kp.privateKey);
        const actual = new Uint8Array(await ec.serializePublicKey(derived));

        // Same x-coordinate, and the ECDH result is identical.
        assertEquals(actual.length, expected.length);
        assertEquals(
          actual.subarray(0, 1 + curve.size),
          expected.subarray(0, 1 + curve.size),
        );
        const other = await ec.generateKeyPair();
        assertEquals(
          new Uint8Array(await ec.dh(other.privateKey, derived)),
          new Uint8Array(await ec.dh(other.privateKey, kp.publicKey)),
        );
      });
    });
  }
});
