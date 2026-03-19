import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { isDeno } from "@hpke/common";

import {
  ContentEncAlg,
  createHpke0Ke,
  createHpke1Ke,
  createHpke2Ke,
  createHpke3,
  createHpke3Ke,
  createHpke4Ke,
  createHpke5Ke,
  createHpke6Ke,
  createHpke7Ke,
  JoseError,
} from "../mod.ts";

describe("JoseEncrypt", () => {
  describe("single recipient with HPKE-3-KE (X25519, AES-128-GCM)", () => {
    it("should seal and open with A128GCM content encryption", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("Key Encryption test");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });

    it("should seal and open with A256GCM content encryption", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("A256GCM test");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });

    it("should produce valid JWE JSON format", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("format check");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );

      // Verify JWE JSON structure
      assertEquals(typeof jwe.protected, "string");
      assertEquals(typeof jwe.iv, "string");
      assertEquals(typeof jwe.ciphertext, "string");
      assertEquals(typeof jwe.tag, "string");
      assertEquals(Array.isArray(jwe.recipients), true);
      assertEquals(jwe.recipients.length, 1);

      // Verify protected header
      const header = JSON.parse(
        atob(jwe.protected.replace(/-/g, "+").replace(/_/g, "/")),
      );
      assertEquals(header.enc, "A128GCM");

      // Verify recipient header
      const rHeader = jwe.recipients[0].header;
      assertEquals(rHeader.alg, "HPKE-3-KE");
      assertEquals(typeof rHeader.ek, "string");
    });

    it("should seal and open with JWE AAD", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("with AAD");
      const aad = new TextEncoder().encode("additional-data");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
        { aad },
      );

      // Verify aad field is present
      assertEquals(typeof jwe.aad, "string");

      const pt = await enc.open(rkp, jwe);
      assertEquals(pt, plaintext);
    });
  });

  describe("single recipient with HPKE-0-KE (P-256, AES-128-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc = createHpke0Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("P-256 KE test");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-1-KE (P-384, HKDF-SHA384, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc = createHpke1Ke(ContentEncAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("P-384 KE test");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  const describeP521 = isDeno() ? describe.ignore : describe;
  describeP521("HPKE-2-KE (P-521, HKDF-SHA512, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc = createHpke2Ke(ContentEncAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("P-521 KE test");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-4-KE (X25519, ChaCha20Poly1305)", () => {
    it("should seal and open with A128GCM content encryption", async () => {
      const enc = createHpke4Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("ChaCha KE test");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-5-KE (X448, HKDF-SHA512, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc = createHpke5Ke(ContentEncAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("X448 KE test");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-6-KE (X448, ChaCha20Poly1305)", () => {
    it("should seal and open with A256GCM content encryption", async () => {
      const enc = createHpke6Ke(ContentEncAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("X448 ChaCha KE test");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-7-KE (P-256, HKDF-SHA256, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc = createHpke7Ke(ContentEncAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("P-256 A256 KE test");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("multiple recipients", () => {
    it("should seal for two recipients and each can open", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp1 = await enc.generateKemKeyPair();
      const rkp2 = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("multi-recipient");
      const jwe = await enc.seal(
        [
          { recipientPublicKey: rkp1.publicKey },
          { recipientPublicKey: rkp2.publicKey },
        ],
        plaintext,
      );

      assertEquals(jwe.recipients.length, 2);

      const pt1 = await enc.open(rkp1, jwe);
      assertEquals(pt1, plaintext);

      const pt2 = await enc.open(rkp2, jwe);
      assertEquals(pt2, plaintext);
    });
  });

  describe("PSK mode", () => {
    it("should seal and open with PSK", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("KE PSK test");
      const psk = {
        id: "ke-psk-id-01",
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey, psk }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe, { psk });

      assertEquals(pt, plaintext);
    });

    it("should fail with mismatched psk_id", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("KE PSK mismatch");
      const psk = {
        id: "ke-psk-id-02",
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey, psk }],
        plaintext,
      );

      await assertRejects(
        async () => {
          await enc.open(rkp, jwe, {
            psk: {
              id: "wrong-psk-id",
              key: psk.key,
            },
          });
        },
        JoseError,
        "No matching recipient found",
      );
    });
  });

  describe("multiple recipients with PSK", () => {
    it("should seal and open with PSK for multiple recipients", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp1 = await enc.generateKemKeyPair();
      const rkp2 = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("multi PSK");
      const psk = {
        id: "shared-psk",
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const jwe = await enc.seal(
        [
          { recipientPublicKey: rkp1.publicKey, psk },
          { recipientPublicKey: rkp2.publicKey, psk },
        ],
        plaintext,
      );

      const pt1 = await enc.open(rkp1, jwe, { psk });
      assertEquals(pt1, plaintext);
      const pt2 = await enc.open(rkp2, jwe, { psk });
      assertEquals(pt2, plaintext);
    });

    it("should seal with mixed PSK/base mode recipients", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp1 = await enc.generateKemKeyPair();
      const rkp2 = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("mixed mode");
      const psk = {
        id: "psk-only-r1",
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const jwe = await enc.seal(
        [
          { recipientPublicKey: rkp1.publicKey, psk },
          { recipientPublicKey: rkp2.publicKey },
        ],
        plaintext,
      );

      const pt1 = await enc.open(rkp1, jwe, { psk });
      assertEquals(pt1, plaintext);
      const pt2 = await enc.open(rkp2, jwe);
      assertEquals(pt2, plaintext);
    });
  });

  describe("kid-based recipient matching", () => {
    it("should match recipient by kid", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp1 = await enc.generateKemKeyPair();
      const rkp2 = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("kid test");
      const jwe = await enc.seal(
        [
          { recipientPublicKey: rkp1.publicKey, kid: "key-1" },
          { recipientPublicKey: rkp2.publicKey, kid: "key-2" },
        ],
        plaintext,
      );

      const pt = await enc.open(rkp2, jwe, { kid: "key-2" });
      assertEquals(pt, plaintext);
    });

    it("should fail when kid does not match any recipient", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("kid miss");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey, kid: "real-kid" }],
        plaintext,
      );

      await assertRejects(
        async () => {
          await enc.open(rkp, jwe, { kid: "wrong-kid" });
        },
        JoseError,
        "No matching recipient found",
      );
    });
  });

  describe("extraInfo round-trip", () => {
    it("should seal and open with extraInfo", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("extra info test");
      const extraInfo = new TextEncoder().encode("my-extra-info");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey, extraInfo }],
        plaintext,
      );
      const pt = await enc.open(rkp, jwe, { extraInfo });

      assertEquals(pt, plaintext);
    });

    it("should fail to open with wrong extraInfo", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("extra mismatch");
      const jwe = await enc.seal(
        [{
          recipientPublicKey: rkp.publicKey,
          extraInfo: new TextEncoder().encode("info-a"),
        }],
        plaintext,
      );

      await assertRejects(
        async () => {
          await enc.open(rkp, jwe, {
            extraInfo: new TextEncoder().encode("info-b"),
          });
        },
        JoseError,
        "No matching recipient found",
      );
    });
  });

  describe("PSK wrong key", () => {
    it("should fail with correct psk_id but wrong psk key", async () => {
      const enc0 = createHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("wrong key");
      const psk = {
        id: "psk-wrong-key",
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const jwe = await enc0.seal(rkp.publicKey, plaintext, { psk });

      await assertRejects(
        async () => {
          await enc0.open(rkp, jwe, {
            psk: {
              id: psk.id,
              key: crypto.getRandomValues(new Uint8Array(32)),
            },
          });
        },
        Error,
      );
    });
  });

  describe("error cases", () => {
    it("should reject empty recipients", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      await assertRejects(
        async () => {
          await enc.seal([], new Uint8Array([1, 2, 3]));
        },
        JoseError,
        "At least one recipient is required",
      );
    });

    it("should fail to open with wrong key", async () => {
      const enc = createHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();
      const wrongKp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("secret");
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );

      await assertRejects(
        async () => {
          await enc.open(wrongKp, jwe);
        },
        JoseError,
        "No matching recipient found",
      );
    });
  });
});
