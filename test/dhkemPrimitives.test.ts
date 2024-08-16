import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import * as errors from "../core/src/errors.ts";
import { KemId } from "../core/src/identifiers.ts";
import { HkdfSha384 } from "../src/kdfs/hkdfSha384.ts";
import { HkdfSha512 } from "../src/kdfs/hkdfSha512.ts";
import { Ec } from "../core/src/kems/dhkemPrimitives/ec.ts";
import { X448 } from "../src/kems/dhkemPrimitives/x448.ts";
import { isDeno } from "../core/src/utils/misc.ts";

import { HkdfSha256 } from "../x/dhkem-x25519/src/hkdfSha256.ts";
import { X25519 } from "../x/dhkem-x25519/src/x25519.ts";

describe("derivePublicKey", () => {
  describe("with valid parameters", () => {
    it("should return a proper public key with Ec(DhkemP256HkdfSha256)", async () => {
      const kdf = new HkdfSha256();
      const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
      const kp = await prim.generateKeyPair();
      const ret = await prim.derivePublicKey(kp.privateKey);
      const bPubKey = await prim.serializePublicKey(kp.publicKey);
      const bRet = await prim.serializePublicKey(ret);

      // assert
      assertEquals(ret.type, "public");
      assertEquals(ret.extractable, true);
      assertEquals(ret.algorithm.name, "ECDH");
      // assertEquals(ret.algorithm.namedCurve, "P-256");
      assertEquals(ret.usages.length, 0);
      assertEquals(new Uint8Array(bRet), new Uint8Array(bPubKey));
    });

    it("should return a proper public key with Ec(DhkemP384HkdfSha384)", async () => {
      const kdf = new HkdfSha384();
      const prim = new Ec(KemId.DhkemP384HkdfSha384, kdf);
      const kp = await prim.generateKeyPair();
      const ret = await prim.derivePublicKey(kp.privateKey);
      const bPubKey = await prim.serializePublicKey(kp.publicKey);
      const bRet = await prim.serializePublicKey(ret);

      // assert
      assertEquals(ret.type, "public");
      assertEquals(ret.extractable, true);
      assertEquals(ret.algorithm.name, "ECDH");
      // assertEquals(ret.algorithm.namedCurve, "P-256");
      assertEquals(ret.usages.length, 0);
      assertEquals(new Uint8Array(bRet), new Uint8Array(bPubKey));
    });

    it("should return a proper public key with Ec(DhkemP521HkdfSha512)", async () => {
      if (isDeno()) {
        return;
      }
      const kdf = new HkdfSha512();
      const prim = new Ec(KemId.DhkemP521HkdfSha512, kdf);
      const kp = await prim.generateKeyPair();
      const ret = await prim.derivePublicKey(kp.privateKey);
      const bPubKey = await prim.serializePublicKey(kp.publicKey);
      const bRet = await prim.serializePublicKey(ret);

      // assert
      assertEquals(ret.type, "public");
      assertEquals(ret.extractable, true);
      assertEquals(ret.algorithm.name, "ECDH");
      // assertEquals(ret.algorithm.namedCurve, "P-256");
      assertEquals(ret.usages.length, 0);
      assertEquals(new Uint8Array(bRet), new Uint8Array(bPubKey));
    });

    it("should return a proper public key with X25519", async () => {
      const kdf = new HkdfSha256();
      const prim = new X25519(kdf);
      const kp = await prim.generateKeyPair();
      const ret = await prim.derivePublicKey(kp.privateKey);
      const bPubKey = await prim.serializePublicKey(kp.publicKey);
      const bRet = await prim.serializePublicKey(ret);

      // assert
      assertEquals(ret.type, "public");
      assertEquals(ret.extractable, true);
      assertEquals(ret.algorithm.name, "X25519");
      // assertEquals(ret.algorithm.namedCurve, "X25519");
      assertEquals(ret.usages.length, 0);
      assertEquals(new Uint8Array(bRet), new Uint8Array(bPubKey));
    });

    it("should return a proper public key with X448", async () => {
      const kdf = new HkdfSha512();
      const prim = new X448(kdf);
      const kp = await prim.generateKeyPair();
      const ret = await prim.derivePublicKey(kp.privateKey);
      const bPubKey = await prim.serializePublicKey(kp.publicKey);
      const bRet = await prim.serializePublicKey(ret);

      // assert
      assertEquals(ret.type, "public");
      assertEquals(ret.extractable, true);
      assertEquals(ret.algorithm.name, "X448");
      // assertEquals(ret.algorithm.namedCurve, "X448");
      assertEquals(ret.usages.length, 0);
      assertEquals(new Uint8Array(bRet), new Uint8Array(bPubKey));
    });
  });

  describe("with invalid parameters", () => {
    it("should throw DeserializeError on Ec(DhkemP256HkdfSha256) with a P-384 private key", async () => {
      const kdf = new HkdfSha256();
      const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
      const kdf2 = new HkdfSha384();
      const prim2 = new Ec(KemId.DhkemP384HkdfSha384, kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    it("should throw DeserializeError on Ec(DhkemP256HkdfSha256) with a P-521 private key", async () => {
      if (isDeno()) {
        return;
      }
      const kdf = new HkdfSha256();
      const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
      const kdf2 = new HkdfSha512();
      const prim2 = new Ec(KemId.DhkemP521HkdfSha512, kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    it("should throw DeserializeError on Ec(DhkemP256HkdfSha256) with a X25519 private key", async () => {
      const kdf = new HkdfSha256();
      const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
      const kdf2 = new HkdfSha256();
      const prim2 = new X25519(kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    it("should throw DeserializeError on Ec(DhkemP256HkdfSha256) with a X448 private key", async () => {
      const kdf = new HkdfSha256();
      const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
      const kdf2 = new HkdfSha512();
      const prim2 = new X448(kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    // it("should throw DeserializeError on Ec(DhkemP256HkdfSha256) with a P-256 public key", async () => {
    //   const kdf = new HkdfSha256();
    //   const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
    //   const kp = await prim.generateKeyPair();

    //   await assertRejects(
    //     () => prim.derivePublicKey(kp.publicKey),
    //     errors.DeserializeError,
    //   );
    // });

    it("should throw DeserializeError on X25519 with a P-256 private key", async () => {
      const kdf = new HkdfSha256();
      const prim = new X25519(kdf);
      const kdf2 = new HkdfSha256();
      const prim2 = new Ec(KemId.DhkemP256HkdfSha256, kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    it("should throw DeserializeError on X25519 with a P-384 private key", async () => {
      const kdf = new HkdfSha256();
      const prim = new X25519(kdf);
      const kdf2 = new HkdfSha384();
      const prim2 = new Ec(KemId.DhkemP384HkdfSha384, kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    it("should throw DeserializeError on X25519 with a P-521 private key", async () => {
      if (isDeno()) {
        return;
      }
      const kdf = new HkdfSha256();
      const prim = new X25519(kdf);
      const kdf2 = new HkdfSha512();
      const prim2 = new Ec(KemId.DhkemP521HkdfSha512, kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    it("should throw DeserializeError on X25519 with a X448 private key", async () => {
      const kdf = new HkdfSha256();
      const prim = new X25519(kdf);
      const kdf2 = new HkdfSha512();
      const prim2 = new X448(kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    it("should throw DeserializeError on X448 with a P-256 private key", async () => {
      const kdf = new HkdfSha512();
      const prim = new X448(kdf);
      const kdf2 = new HkdfSha256();
      const prim2 = new Ec(KemId.DhkemP256HkdfSha256, kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    it("should throw DeserializeError on X448 with a P-384 private key", async () => {
      const kdf = new HkdfSha512();
      const prim = new X448(kdf);
      const kdf2 = new HkdfSha384();
      const prim2 = new Ec(KemId.DhkemP384HkdfSha384, kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    it("should throw DeserializeError on X448 with a P-521 private key", async () => {
      if (isDeno()) {
        return;
      }
      const kdf = new HkdfSha512();
      const prim = new X448(kdf);
      const kdf2 = new HkdfSha512();
      const prim2 = new Ec(KemId.DhkemP521HkdfSha512, kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });

    it("should throw DeserializeError on X448 with a X25519 private key", async () => {
      const kdf = new HkdfSha512();
      const prim = new X448(kdf);
      const kdf2 = new HkdfSha256();
      const prim2 = new X25519(kdf2);
      const kp = await prim2.generateKeyPair();

      await assertRejects(
        () => prim.derivePublicKey(kp.privateKey),
        errors.DeserializeError,
      );
    });
  });
});
