import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { isDeno } from "@hpke/common";

import {
  ContentAlg,
  CoseError,
  createHpke0Ke,
  createHpke1Ke,
  createHpke2Ke,
  createHpke3Ke,
  createHpke4Ke,
  createHpke5Ke,
  createHpke6Ke,
  createHpke7Ke,
} from "../mod.ts";

describe("CoseEncrypt", () => {
  describe("single recipient with HPKE-3-KE (X25519, AES-128-GCM)", () => {
    it("should seal and open with A128GCM content encryption", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("Key Encryption test");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct);

      assertEquals(pt, plaintext);
    });

    it("should seal and open with A256GCM content encryption", async () => {
      const enc = createHpke3Ke(ContentAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("A256GCM test");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct);

      assertEquals(pt, plaintext);
    });

    it("should seal and open with external AAD", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("with ext AAD");
      const externalAad = new Uint8Array([0xde, 0xad]);
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
        { externalAad },
      );
      const pt = await enc.open(rkp, ct, { externalAad });

      assertEquals(pt, plaintext);
    });
  });

  describe("single recipient with HPKE-0-KE (P-256, AES-128-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc = createHpke0Ke(ContentAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("P-256 KE test");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-1-KE (P-384, HKDF-SHA384, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc = createHpke1Ke(ContentAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("P-384 KE test");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  const describeP521 = isDeno() ? describe.ignore : describe;
  describeP521("HPKE-2-KE (P-521, HKDF-SHA512, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc = createHpke2Ke(ContentAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("P-521 KE test");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-4-KE (X25519, ChaCha20Poly1305) with ChaCha20 content", () => {
    it("should seal and open with ChaCha20Poly1305 content encryption", async () => {
      const enc = createHpke4Ke(ContentAlg.CHACHA20POLY1305);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("ChaCha KE test");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-5-KE (X448, HKDF-SHA512, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc = createHpke5Ke(ContentAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("X448 KE test");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-6-KE (X448, ChaCha20Poly1305) with ChaCha20 content", () => {
    it("should seal and open with ChaCha20Poly1305 content encryption", async () => {
      const enc = createHpke6Ke(ContentAlg.CHACHA20POLY1305);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("X448 ChaCha KE test");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-7-KE (P-256, HKDF-SHA256, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc = createHpke7Ke(ContentAlg.A256GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("P-256 A256 KE test");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("multiple recipients", () => {
    it("should seal for two recipients and each can open", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp1 = await enc.generateKemKeyPair();
      const rkp2 = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("multi-recipient");
      const ct = await enc.seal(
        [
          { recipientPublicKey: rkp1.publicKey },
          { recipientPublicKey: rkp2.publicKey },
        ],
        plaintext,
      );

      // Recipient 1 can open
      const pt1 = await enc.open(rkp1, ct);
      assertEquals(pt1, plaintext);

      // Recipient 2 can open
      const pt2 = await enc.open(rkp2, ct);
      assertEquals(pt2, plaintext);
    });
  });

  describe("PSK mode", () => {
    it("should seal and open with PSK", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("KE PSK test");
      const psk = {
        id: new TextEncoder().encode("ke-psk-id-01"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey, psk }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct, { psk });

      assertEquals(pt, plaintext);
    });

    it("should fail with mismatched psk_id", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("KE PSK mismatch");
      const psk = {
        id: new TextEncoder().encode("ke-psk-id-02"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey, psk }],
        plaintext,
      );

      await assertRejects(
        async () => {
          await enc.open(rkp, ct, {
            psk: {
              id: new TextEncoder().encode("wrong-psk-id"),
              key: psk.key,
            },
          });
        },
        CoseError,
        "No matching recipient found",
      );
    });
  });

  describe("multiple recipients with PSK", () => {
    it("should seal and open with PSK for multiple recipients", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp1 = await enc.generateKemKeyPair();
      const rkp2 = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("multi PSK");
      const psk = {
        id: new TextEncoder().encode("shared-psk"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const ct = await enc.seal(
        [
          { recipientPublicKey: rkp1.publicKey, psk },
          { recipientPublicKey: rkp2.publicKey, psk },
        ],
        plaintext,
      );

      const pt1 = await enc.open(rkp1, ct, { psk });
      assertEquals(pt1, plaintext);
      const pt2 = await enc.open(rkp2, ct, { psk });
      assertEquals(pt2, plaintext);
    });

    it("should seal with different PSKs per recipient", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp1 = await enc.generateKemKeyPair();
      const rkp2 = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("diff PSK");
      const psk1 = {
        id: new TextEncoder().encode("psk-r1"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const psk2 = {
        id: new TextEncoder().encode("psk-r2"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const ct = await enc.seal(
        [
          { recipientPublicKey: rkp1.publicKey, psk: psk1 },
          { recipientPublicKey: rkp2.publicKey, psk: psk2 },
        ],
        plaintext,
      );

      const pt1 = await enc.open(rkp1, ct, { psk: psk1 });
      assertEquals(pt1, plaintext);
      const pt2 = await enc.open(rkp2, ct, { psk: psk2 });
      assertEquals(pt2, plaintext);
    });

    it("should seal with mixed PSK/base mode recipients", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp1 = await enc.generateKemKeyPair();
      const rkp2 = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("mixed mode");
      const psk = {
        id: new TextEncoder().encode("psk-only-r1"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const ct = await enc.seal(
        [
          { recipientPublicKey: rkp1.publicKey, psk },
          { recipientPublicKey: rkp2.publicKey },
        ],
        plaintext,
      );

      // Recipient 1 opens with PSK
      const pt1 = await enc.open(rkp1, ct, { psk });
      assertEquals(pt1, plaintext);
      // Recipient 2 opens without PSK (base mode)
      const pt2 = await enc.open(rkp2, ct);
      assertEquals(pt2, plaintext);
    });
  });

  describe("Encrypt0 PSK wrong key", () => {
    it("should fail with correct psk_id but wrong psk key", async () => {
      const { createHpke3: createHpke3Ie } = await import("../mod.ts");
      const enc0 = createHpke3Ie();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("wrong key");
      const psk = {
        id: new TextEncoder().encode("psk-wrong-key"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const ct = await enc0.seal(rkp.publicKey, plaintext, { psk });

      await assertRejects(
        async () => {
          await enc0.open(rkp, ct, {
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

  describe("kid-based recipient matching", () => {
    it("should match recipient by kid", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp1 = await enc.generateKemKeyPair();
      const rkp2 = await enc.generateKemKeyPair();

      const kid1 = new TextEncoder().encode("key-1");
      const kid2 = new TextEncoder().encode("key-2");

      const plaintext = new TextEncoder().encode("kid test");
      const ct = await enc.seal(
        [
          { recipientPublicKey: rkp1.publicKey, kid: kid1 },
          { recipientPublicKey: rkp2.publicKey, kid: kid2 },
        ],
        plaintext,
      );

      // Open with kid matching recipient 2
      const pt = await enc.open(rkp2, ct, { kid: kid2 });
      assertEquals(pt, plaintext);
    });

    it("should fail when kid does not match any recipient", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("kid miss");
      const ct = await enc.seal(
        [{
          recipientPublicKey: rkp.publicKey,
          kid: new TextEncoder().encode("real-kid"),
        }],
        plaintext,
      );

      await assertRejects(
        async () => {
          await enc.open(rkp, ct, {
            kid: new TextEncoder().encode("wrong-kid"),
          });
        },
        CoseError,
        "No matching recipient found",
      );
    });
  });

  describe("extraInfo round-trip", () => {
    it("should seal and open with extraInfo", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("extra info test");
      const extraInfo = new TextEncoder().encode("my-extra-info");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey, extraInfo }],
        plaintext,
      );
      const pt = await enc.open(rkp, ct, { extraInfo });

      assertEquals(pt, plaintext);
    });

    it("should fail to open with wrong extraInfo", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("extra mismatch");
      const ct = await enc.seal(
        [{
          recipientPublicKey: rkp.publicKey,
          extraInfo: new TextEncoder().encode("info-a"),
        }],
        plaintext,
      );

      await assertRejects(
        async () => {
          await enc.open(rkp, ct, {
            extraInfo: new TextEncoder().encode("info-b"),
          });
        },
        CoseError,
        "No matching recipient found",
      );
    });
  });

  describe("Encrypt0 kid", () => {
    it("should seal and open with kid in protected header", async () => {
      const { createHpke3: createHpke3Ie } = await import("../mod.ts");
      const enc0 = createHpke3Ie();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("kid encrypt0");
      const kid = new TextEncoder().encode("my-key-id");
      const ct = await enc0.seal(rkp.publicKey, plaintext, { kid });
      const pt = await enc0.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("error cases", () => {
    it("should reject empty recipients", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      await assertRejects(
        async () => {
          await enc.seal([], new Uint8Array([1, 2, 3]));
        },
        CoseError,
        "At least one recipient is required",
      );
    });

    it("should fail to open with wrong key", async () => {
      const enc = createHpke3Ke(ContentAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();
      const wrongKp = await enc.generateKemKeyPair();

      const plaintext = new TextEncoder().encode("secret");
      const ct = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );

      await assertRejects(
        async () => {
          await enc.open(wrongKp, ct);
        },
        CoseError,
        "No matching recipient found",
      );
    });
  });
});
