import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  createJoseHpke0,
  createJoseHpke1,
  createJoseHpke2,
  createJoseHpke3,
  createJoseHpke4,
  createJoseHpke5,
  createJoseHpke6,
  createJoseHpke7,
  JoseError,
} from "../mod.ts";
import { decodeBase64Url, encodeBase64Url } from "../src/utils.ts";

describe("JoseEncrypt0", () => {
  describe("HPKE-0 (P-256, HKDF-SHA256, AES-128-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createJoseHpke0();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("Hello, JOSE-HPKE!");
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });

    it("should produce valid JWE compact format", async () => {
      const enc0 = createJoseHpke0();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("format check");
      const jwe = await enc0.seal(rkp.publicKey, plaintext);

      // JWE compact: header.encryptedKey.iv.ciphertext.tag
      const parts = jwe.split(".");
      assertEquals(parts.length, 5);
      // IV should be empty
      assertEquals(parts[2], "");
      // Tag should be empty
      assertEquals(parts[4], "");
      // Header should decode to valid JSON with alg
      const header = JSON.parse(
        atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")),
      );
      assertEquals(header.alg, "HPKE-0");
      assertEquals(header.enc, undefined);
    });

    it("should seal and open with info", async () => {
      const enc0 = createJoseHpke0();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("with info");
      const info = new TextEncoder().encode("app-context");
      const jwe = await enc0.seal(rkp.publicKey, plaintext, { info });
      const pt = await enc0.open(rkp, jwe, { info });

      assertEquals(pt, plaintext);
    });

    it("should seal and open with privateKey directly", async () => {
      const enc0 = createJoseHpke0();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("private key");
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp.privateKey, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-1 (P-384, HKDF-SHA384, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createJoseHpke1();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("P-384 test");
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-2 (P-521, HKDF-SHA512, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createJoseHpke2();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("P-521 test");
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-3 (X25519, HKDF-SHA256, AES-128-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("X25519 test");
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });

    it("should seal and open with info", async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("full options");
      const info = new TextEncoder().encode("context");
      const jwe = await enc0.seal(rkp.publicKey, plaintext, { info });
      const pt = await enc0.open(rkp, jwe, { info });

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-4 (X25519, HKDF-SHA256, ChaCha20Poly1305)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createJoseHpke4();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("ChaCha test");
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-5 (X448, HKDF-SHA512, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createJoseHpke5();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("X448 test");
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-6 (X448, HKDF-SHA512, ChaCha20Poly1305)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createJoseHpke6();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("X448 ChaCha test");
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-7 (P-256, HKDF-SHA256, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createJoseHpke7();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("P-256 AES-256 test");
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("PSK mode", () => {
    it("should seal and open with PSK", async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("PSK test");
      const psk = {
        id: new TextEncoder().encode("psk-id-01"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const jwe = await enc0.seal(rkp.publicKey, plaintext, { psk });
      const pt = await enc0.open(rkp, jwe, { psk });

      assertEquals(pt, plaintext);
    });

    it("should carry psk_id as BASE64URL(id) and use id as the HPKE psk_id", async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();
      // Not valid UTF-8, so it cannot pass through a text encoding unchanged.
      const psk = {
        id: new Uint8Array([0xff, 0xfe, 0xfd]),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const plaintext = new TextEncoder().encode("PSK encoding");

      const jwe = await enc0.seal(rkp.publicKey, plaintext, { psk });
      const header = JSON.parse(
        new TextDecoder().decode(decodeBase64Url(jwe.split(".")[0])),
      );
      assertEquals(header.psk_id, "__79");

      // Encrypt directly with HPKE so the psk_id handling of seal() is not
      // what open() is being checked against.
      const encodedHeader = encodeBase64Url(
        new TextEncoder().encode(
          JSON.stringify({ alg: "HPKE-3", psk_id: "__79" }),
        ),
      );
      const ctx = await enc0.suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        psk,
      });
      const ct = await ctx.seal(
        plaintext,
        new TextEncoder().encode(encodedHeader),
      );
      const pt = await enc0.open(
        rkp,
        `${encodedHeader}.${encodeBase64Url(new Uint8Array(ctx.enc))}..${
          encodeBase64Url(new Uint8Array(ct))
        }.`,
        { psk },
      );
      assertEquals(pt, plaintext);
    });

    it("should fail to open without PSK when sealed with PSK", async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("PSK required");
      const psk = {
        id: new TextEncoder().encode("psk-id-02"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const jwe = await enc0.seal(rkp.publicKey, plaintext, { psk });

      await assertRejects(
        async () => {
          await enc0.open(rkp, jwe);
        },
        Error,
      );
    });

    it("should fail with mismatched psk_id", async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("PSK mismatch");
      const psk = {
        id: new TextEncoder().encode("psk-id-03"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const jwe = await enc0.seal(rkp.publicKey, plaintext, { psk });

      await assertRejects(
        async () => {
          await enc0.open(rkp, jwe, {
            psk: {
              id: new TextEncoder().encode("wrong-psk-id"),
              key: psk.key,
            },
          });
        },
        JoseError,
        "psk_id mismatch",
      );
    });
  });

  describe("kid", () => {
    it("should seal and open with kid in protected header", async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("kid test");
      const jwe = await enc0.seal(rkp.publicKey, plaintext, { kid: "key-1" });

      // Verify kid is in the header
      const parts = jwe.split(".");
      const header = JSON.parse(
        atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")),
      );
      assertEquals(header.kid, "key-1");

      const pt = await enc0.open(rkp, jwe);
      assertEquals(pt, plaintext);
    });
  });

  describe("empty plaintext", () => {
    it("should seal and open empty data", async () => {
      const enc0 = createJoseHpke0();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new Uint8Array(0);
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("large plaintext", () => {
    it("should seal and open 64KB data", async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = crypto.getRandomValues(new Uint8Array(65536));
      const jwe = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, jwe);

      assertEquals(pt, plaintext);
    });
  });

  describe("cross-algorithm rejection", () => {
    it("should fail when different algorithms are used", async () => {
      const enc0_3 = createJoseHpke3();
      const enc0_0 = createJoseHpke0();
      const rkp3 = await enc0_3.suite.kem.generateKeyPair();
      const rkp0 = await enc0_0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("cross alg");
      const jwe = await enc0_3.seal(rkp3.publicKey, plaintext);

      await assertRejects(
        async () => {
          await enc0_0.open(rkp0, jwe);
        },
        JoseError,
        "Algorithm mismatch",
      );
    });
  });
});
