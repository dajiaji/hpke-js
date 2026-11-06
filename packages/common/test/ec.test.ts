import { assertEquals, assertInstanceOf, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  Ec,
  EC_P_256,
  EC_P_384,
  EC_P_521,
  type EcCurve,
  EcDhkemPrimitives,
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
  type KdfInterface,
  KemId,
  NotSupportedError,
} from "../mod.ts";

// suite_id = concat("KEM", I2OSP(kem_id, 2))
function kemKdf(kdf: KdfInterface, kemId: number): KdfInterface {
  kdf.init(new Uint8Array([75, 69, 77, kemId >> 8, kemId & 0xff]));
  return kdf;
}

const CASES: [KemId, EcCurve, () => KdfInterface][] = [
  [
    KemId.DhkemP256HkdfSha256,
    EC_P_256,
    () => kemKdf(new HkdfSha256Native(), KemId.DhkemP256HkdfSha256),
  ],
  [
    KemId.DhkemP384HkdfSha384,
    EC_P_384,
    () => kemKdf(new HkdfSha384Native(), KemId.DhkemP384HkdfSha384),
  ],
  [
    KemId.DhkemP521HkdfSha512,
    EC_P_521,
    () => kemKdf(new HkdfSha512Native(), KemId.DhkemP521HkdfSha512),
  ],
];

const IKM = /* @__PURE__ */ new Uint8Array(32).fill(7);

describe("Ec (deprecated)", () => {
  for (const [kemId, curve, kdf] of CASES) {
    describe(curve.namedCurve, () => {
      it("should be an EcDhkemPrimitives", () => {
        assertInstanceOf(new Ec(kemId, kdf()), EcDhkemPrimitives);
      });

      it("should behave the same as EcDhkemPrimitives with the matching curve", async () => {
        const ec = new Ec(kemId, kdf());
        const prim = new EcDhkemPrimitives(curve, kdf());
        const kp1 = await ec.deriveKeyPair(IKM);
        const kp2 = await prim.deriveKeyPair(IKM);
        assertEquals(
          new Uint8Array(await ec.serializePrivateKey(kp1.privateKey)),
          new Uint8Array(await prim.serializePrivateKey(kp2.privateKey)),
        );
        assertEquals(
          new Uint8Array(await ec.serializePublicKey(kp1.publicKey)),
          new Uint8Array(await prim.serializePublicKey(kp2.publicKey)),
        );
        // Keys are interchangeable between the two.
        const pk = await prim.deserializePublicKey(
          await ec.serializePublicKey(kp1.publicKey),
        );
        assertEquals(
          new Uint8Array(await ec.dh(kp2.privateKey, pk)),
          new Uint8Array(await prim.dh(kp1.privateKey, kp2.publicKey)),
        );
      });

      it("should generate keys on the selected curve", async () => {
        const ec = new Ec(kemId, kdf());
        const kp = await ec.generateKeyPair();
        assertEquals(
          (kp.publicKey.algorithm as EcKeyAlgorithm).namedCurve,
          curve.namedCurve,
        );
        assertEquals(
          new Uint8Array(await ec.serializePublicKey(kp.publicKey)).length,
          1 + curve.size * 2,
        );
        assertEquals(
          new Uint8Array(await ec.serializePrivateKey(kp.privateKey)).length,
          curve.size,
        );
      });
    });
  }

  for (
    const kemId of [
      KemId.NotAssigned,
      KemId.DhkemSecp256k1HkdfSha256,
      KemId.DhkemX25519HkdfSha256,
      KemId.DhkemX448HkdfSha512,
      KemId.MlKem768,
      KemId.XWing,
    ]
  ) {
    it(
      `should throw NotSupportedError for KEM ID 0x${kemId.toString(16)}`,
      () => {
        assertThrows(
          () => new Ec(kemId, new HkdfSha512Native()),
          NotSupportedError,
          "Unsupported KEM ID for Ec",
        );
      },
    );
  }
});
