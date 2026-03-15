import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { isDeno } from "@hpke/common";

import {
  CoseError,
  createHpke0,
  createHpke1,
  createHpke2,
  createHpke3,
  createHpke4,
  createHpke5,
  createHpke6,
  createHpke7,
} from "../mod.ts";

describe("CoseEncrypt0", () => {
  describe("HPKE-0 (P-256, HKDF-SHA256, AES-128-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createHpke0();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("Hello, COSE-HPKE!");
      const ct = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, ct);

      assertEquals(pt, plaintext);
    });

    it("should seal and open with external AAD", async () => {
      const enc0 = createHpke0();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("with AAD");
      const externalAad = new Uint8Array([0xaa, 0xbb, 0xcc]);
      const ct = await enc0.seal(rkp.publicKey, plaintext, { externalAad });
      const pt = await enc0.open(rkp, ct, { externalAad });

      assertEquals(pt, plaintext);
    });

    it("should seal and open with info", async () => {
      const enc0 = createHpke0();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("with info");
      const info = new TextEncoder().encode("app-context");
      const ct = await enc0.seal(rkp.publicKey, plaintext, { info });
      const pt = await enc0.open(rkp, ct, { info });

      assertEquals(pt, plaintext);
    });

    it("should seal and open with privateKey directly", async () => {
      const enc0 = createHpke0();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("private key");
      const ct = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp.privateKey, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-1 (P-384, HKDF-SHA384, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createHpke1();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("P-384 test");
      const ct = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  const describeP521 = isDeno() ? describe.ignore : describe;
  describeP521("HPKE-2 (P-521, HKDF-SHA512, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createHpke2();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("P-521 test");
      const ct = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-3 (X25519, HKDF-SHA256, AES-128-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("X25519 test");
      const ct = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, ct);

      assertEquals(pt, plaintext);
    });

    it("should seal and open with external AAD and info", async () => {
      const enc0 = createHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("full options");
      const opts = {
        externalAad: new Uint8Array([1, 2, 3]),
        info: new TextEncoder().encode("context"),
      };
      const ct = await enc0.seal(rkp.publicKey, plaintext, opts);
      const pt = await enc0.open(rkp, ct, opts);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-4 (X25519, HKDF-SHA256, ChaCha20Poly1305)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createHpke4();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("ChaCha test");
      const ct = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-5 (X448, HKDF-SHA512, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createHpke5();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("X448 test");
      const ct = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-6 (X448, HKDF-SHA512, ChaCha20Poly1305)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createHpke6();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("X448 ChaCha test");
      const ct = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("HPKE-7 (P-256, HKDF-SHA256, AES-256-GCM)", () => {
    it("should seal and open a message", async () => {
      const enc0 = createHpke7();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("P-256 AES-256 test");
      const ct = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });

  describe("PSK mode", () => {
    it("should seal and open with PSK", async () => {
      const enc0 = createHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("PSK test");
      const psk = {
        id: new TextEncoder().encode("psk-id-01"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const ct = await enc0.seal(rkp.publicKey, plaintext, { psk });
      const pt = await enc0.open(rkp, ct, { psk });

      assertEquals(pt, plaintext);
    });

    it("should fail to open without PSK when sealed with PSK", async () => {
      const enc0 = createHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("PSK required");
      const psk = {
        id: new TextEncoder().encode("psk-id-02"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const ct = await enc0.seal(rkp.publicKey, plaintext, { psk });

      await assertRejects(
        async () => {
          await enc0.open(rkp, ct);
        },
        Error,
      );
    });

    it("should fail with mismatched psk_id", async () => {
      const enc0 = createHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new TextEncoder().encode("PSK mismatch");
      const psk = {
        id: new TextEncoder().encode("psk-id-03"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      };
      const ct = await enc0.seal(rkp.publicKey, plaintext, { psk });

      await assertRejects(
        async () => {
          await enc0.open(rkp, ct, {
            psk: {
              id: new TextEncoder().encode("wrong-psk-id"),
              key: psk.key,
            },
          });
        },
        CoseError,
        "psk_id mismatch",
      );
    });
  });

  describe("empty plaintext", () => {
    it("should seal and open empty data", async () => {
      const enc0 = createHpke0();
      const rkp = await enc0.suite.kem.generateKeyPair();

      const plaintext = new Uint8Array(0);
      const ct = await enc0.seal(rkp.publicKey, plaintext);
      const pt = await enc0.open(rkp, ct);

      assertEquals(pt, plaintext);
    });
  });
});
