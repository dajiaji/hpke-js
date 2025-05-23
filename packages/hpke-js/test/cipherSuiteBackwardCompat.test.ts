import { assertEquals, assertRejects, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { concat, hexToBytes, isDeno, loadCrypto } from "@hpke/common";
import {
  DeserializeError,
  InvalidParamError,
  NotSupportedError,
} from "@hpke/core";

import { Aead, Kdf, Kem } from "../mod.ts"; // deprecated identifiers as the test target.
import { CipherSuite } from "../mod.ts";

describe("CipherSuite(backward-compat)", () => {
  // RFC9180 A.1.
  describe("constructor with DhkemX25519HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      // assert
      assertEquals(suite.kem.id, Kem.DhkemX25519HkdfSha256);
      assertEquals(suite.kem.id, 0x0020);
      assertEquals(suite.kem.secretSize, 32);
      assertEquals(suite.kem.encSize, 32);
      assertEquals(suite.kem.publicKeySize, 32);
      assertEquals(suite.kem.privateKeySize, 32);
      assertEquals(suite.kdf.id, Kdf.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, Aead.Aes128Gcm);
      assertEquals(suite.aead.id, 0x0001);
    });
  });

  // RFC9180 A.2.
  describe("constructor with DhkemX25519HkdfSha256/HkdfSha256/ChaCha20Poly1305", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Chacha20Poly1305,
      });

      // assert
      assertEquals(suite.kem.id, Kem.DhkemX25519HkdfSha256);
      assertEquals(suite.kem.id, 0x0020);
      assertEquals(suite.kdf.id, Kdf.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, Aead.Chacha20Poly1305);
      assertEquals(suite.aead.id, 0x0003);
    });
  });

  // RFC9180 A.3.
  describe("constructor with DhkemP256HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      // assert
      assertEquals(suite.kem.id, Kem.DhkemP256HkdfSha256);
      assertEquals(suite.kem.id, 0x0010);
      assertEquals(suite.kdf.id, Kdf.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, Aead.Aes128Gcm);
      assertEquals(suite.aead.id, 0x0001);
    });
  });

  // RFC9180 A.4.
  describe("constructor with DhkemP256HkdfSha256/HkdfSha512/Aes128Gcm", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes128Gcm,
      });

      // assert
      assertEquals(suite.kem.id, Kem.DhkemP256HkdfSha256);
      assertEquals(suite.kem.id, 0x0010);
      assertEquals(suite.kdf.id, Kdf.HkdfSha512);
      assertEquals(suite.kdf.id, 0x0003);
      assertEquals(suite.aead.id, Aead.Aes128Gcm);
      assertEquals(suite.aead.id, 0x0001);
    });
  });

  // RFC9180 A.5.
  describe("constructor with DhkemP256HkdfSha256/HkdfSha256/ChaCha20Poly1305", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Chacha20Poly1305,
      });

      // assert
      assertEquals(suite.kem.id, Kem.DhkemP256HkdfSha256);
      assertEquals(suite.kem.id, 0x0010);
      assertEquals(suite.kdf.id, Kdf.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, Aead.Chacha20Poly1305);
      assertEquals(suite.aead.id, 0x0003);
    });
  });

  // RFC9180 A.6.
  describe("constructor with DhkemP521HkdfSha512/HkdfSha512/Aes256Gcm", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP521HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes256Gcm,
      });

      // assert
      assertEquals(suite.kem.id, Kem.DhkemP521HkdfSha512);
      assertEquals(suite.kem.id, 0x0012);
      assertEquals(suite.kdf.id, Kdf.HkdfSha512);
      assertEquals(suite.kdf.id, 0x0003);
      assertEquals(suite.aead.id, Aead.Aes256Gcm);
      assertEquals(suite.aead.id, 0x0002);
    });
  });

  // RFC9180 A.7.
  describe("constructor with DhkemP256HkdfSha256/HkdfSha256/ExportOnly", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      // assert
      assertEquals(suite.kem.id, Kem.DhkemP256HkdfSha256);
      assertEquals(suite.kem.id, 0x0010);
      assertEquals(suite.kdf.id, Kdf.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, Aead.ExportOnly);
      assertEquals(suite.aead.id, 0xFFFF);
    });
  });

  describe("constructor with DhkemSecp256KHkdfSha256/HkdfSha256/ExportOnly", () => {
    it("should throw InvalidParamError", async () => {
      // assert
      await assertThrows(
        () =>
          new CipherSuite({
            kem: Kem.DhkemSecp256k1HkdfSha256,
            kdf: Kdf.HkdfSha256,
            aead: Aead.ExportOnly,
          }),
        InvalidParamError,
        "The KEM (19) cannot be specified by KemId. Use submodule for the KEM",
      );
    });
  });

  describe("A README example of Base mode", () => {
    it("should work normally with generateKeyPair", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), NotSupportedError);
      await assertRejects(() => sender.open(ct), NotSupportedError);
    });

    it("should work normally with importKey('jwk')", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const jwkPkR = {
        kty: "EC",
        crv: "P-256",
        kid: "P-256-01",
        x: "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
        y: "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
        key_ops: [],
      };
      const pkR = await suite.importKey("jwk", jwkPkR, true);

      const sender = await suite.createSenderContext({
        recipientPublicKey: pkR,
      });

      const jwkSkR = {
        kty: "EC",
        crv: "P-256",
        kid: "P-256-01",
        x: "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
        y: "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
        d: "kwibx3gas6Kz1V2fyQHKSnr-ybflddSjN0eOnbmLmyo",
        key_ops: ["deriveBits"],
      };
      const skR = await suite.importKey("jwk", jwkSkR, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: skR,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), NotSupportedError);
      await assertRejects(() => sender.open(ct), NotSupportedError);
    });
  });

  describe("A README example of Base mode (Kem.DhkemP384HkdfSha384/Kdf.HkdfSha384)", () => {
    it("should work normally with generateKeyPair", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with importKey('jwk')", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const jwkPkR = {
        kty: "EC",
        crv: "P-384",
        kid: "P-384-01",
        x: "_XyN9woHaS0mPimSW-etwJMEDSzxIMjp4PjezavU8SHJoClz1bQrcmPb1ZJxHxhI",
        y: "GCNfc32p9sRotx7u2oDGJ3Eqz6q5zPHLdizNn83oRsUTN31eCWfGLHWRury3xF50",
        key_ops: [],
      };
      const pkR = await suite.importKey("jwk", jwkPkR, true);

      const sender = await suite.createSenderContext({
        recipientPublicKey: pkR,
      });

      const jwkSkR = {
        kty: "EC",
        crv: "P-384",
        kid: "P-384-01",
        x: "_XyN9woHaS0mPimSW-etwJMEDSzxIMjp4PjezavU8SHJoClz1bQrcmPb1ZJxHxhI",
        y: "GCNfc32p9sRotx7u2oDGJ3Eqz6q5zPHLdizNn83oRsUTN31eCWfGLHWRury3xF50",
        d: "1pImEKbrr771-RKi8Tb7tou_WjiR7kwui_nMu16449rk3lzAqf9buUhTkJ-pogkb",
        key_ops: ["deriveBits"],
      };
      const skR = await suite.importKey("jwk", jwkSkR, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: skR,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), NotSupportedError);
      await assertRejects(() => sender.open(ct), NotSupportedError);
    });
  });

  describe("A README example of Base mode (Kem.DhkemP521HkdfSha512/Kdf.HkdfSha512)", () => {
    it("should work normally with generateKeyPair", async () => {
      if (isDeno()) {
        return;
      }

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP521HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with importKey('jwk')", async () => {
      if (isDeno()) {
        return;
      }

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP521HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes128Gcm,
      });

      const jwkPkR = {
        kty: "EC",
        crv: "P-521",
        kid: "P-521-01",
        x: "APkZitSJMJUMB-iPCt47sWu_CrnUHg6IAR4qjmHON-2u41Rjg6DNOS0LZYJJt-AVH5NgGVi8ElIfjo71b9HXCTOc",
        y: "ASx-Cb--149HJ-e1KlSaY-1BOhwOdcTkxSt8BGbW7_hnGfzHsoXM3ywwNcp1Yad-FHUKwmCyMelMQEn2Rh4V2l3I",
        key_ops: [],
      };
      const pkR = await suite.importKey("jwk", jwkPkR, true);

      const sender = await suite.createSenderContext({
        recipientPublicKey: pkR,
      });

      const jwkSkR = {
        kty: "EC",
        crv: "P-521",
        kid: "P-521-01",
        x: "APkZitSJMJUMB-iPCt47sWu_CrnUHg6IAR4qjmHON-2u41Rjg6DNOS0LZYJJt-AVH5NgGVi8ElIfjo71b9HXCTOc",
        y: "ASx-Cb--149HJ-e1KlSaY-1BOhwOdcTkxSt8BGbW7_hnGfzHsoXM3ywwNcp1Yad-FHUKwmCyMelMQEn2Rh4V2l3I",
        d: "ADYyo73ZKicOjwGDYQ_ybZKnVzdAcxGm9OVAxQjzgVM4jaS-Iwtkz90oLdDz3shgKlDgtRK2Aa9lMhqR94hBo4IE",
        key_ops: ["deriveBits"],
      };
      const skR = await suite.importKey("jwk", jwkSkR, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: skR,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), NotSupportedError);
      await assertRejects(() => sender.open(ct), NotSupportedError);
    });
  });

  describe("A README example of Base mode (Kem.DhkemX25519HkdfSha256/Kdf.HkdfSha256)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with importKey('jwk')", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const jwkPkR = {
        kty: "OKP",
        crv: "X25519",
        kid: "X25519-01",
        x: "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
        key_ops: [],
      };
      const pkR = await suite.importKey("jwk", jwkPkR, true);

      const sender = await suite.createSenderContext({
        recipientPublicKey: pkR,
      });

      const jwkSkR = {
        kty: "OKP",
        crv: "X25519",
        kid: "X25519-01",
        x: "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
        d: "vsJ1oX5NNi0IGdwGldiac75r-Utmq3Jq4LGv48Q_Qc4",
        key_ops: ["deriveBits"],
      };
      const skR = await suite.importKey("jwk", jwkSkR, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: skR,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), NotSupportedError);
      await assertRejects(() => sender.open(ct), NotSupportedError);
    });
  });

  describe("A README example of Base mode (Kem.DhkemX448HkdfSha256/Kdf.HkdfSha512)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX448HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes256Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with importKey('jwk')", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX448HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes256Gcm,
      });

      const jwkPkR = {
        kty: "OKP",
        crv: "X448",
        kid: "X448-01",
        x: "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
        key_ops: [],
      };
      const pkR = await suite.importKey("jwk", jwkPkR, true);

      const sender = await suite.createSenderContext({
        recipientPublicKey: pkR,
      });

      const jwkSkR = {
        kty: "OKP",
        crv: "X448",
        kid: "X448-01",
        x: "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
        d: "rJJRG3nshyCtd9CgXld8aNaB9YXKR0UOi7zj7hApg9YH4XdBO0G8NcAFNz_uPH2GnCZVcSDgV5c",
        key_ops: ["deriveBits"],
      };
      const skR = await suite.importKey("jwk", jwkSkR, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: skR,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), NotSupportedError);
      await assertRejects(() => sender.open(ct), NotSupportedError);
    });
  });

  describe("A README example of Base mode (ExportOnly)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      const te = new TextEncoder();

      // export
      const pskS = sender.export(
        te.encode("jugemujugemu").buffer as ArrayBuffer,
        32,
      );
      const pskR = recipient.export(
        te.encode("jugemujugemu").buffer as ArrayBuffer,
        32,
      );
      assertEquals(pskR, pskS);

      // other functions are disabled.
      await assertRejects(
        () => sender.seal(te.encode("my-secret-message").buffer as ArrayBuffer),
        NotSupportedError,
      );
      await assertRejects(
        () => sender.open(te.encode("xxxxxxxxxxxxxxxxx").buffer as ArrayBuffer),
        NotSupportedError,
      );
    });
  });

  describe("A README example of Base mode (ExportOnly/X25519)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      const te = new TextEncoder();

      // export
      const pskS = sender.export(
        te.encode("jugemujugemu").buffer as ArrayBuffer,
        32,
      );
      const pskR = recipient.export(
        te.encode("jugemujugemu").buffer as ArrayBuffer,
        32,
      );
      assertEquals(pskR, pskS);

      // other functions are disabled.
      await assertRejects(
        () => sender.seal(te.encode("my-secret-message").buffer as ArrayBuffer),
        NotSupportedError,
      );
      await assertRejects(
        () => sender.open(te.encode("xxxxxxxxxxxxxxxxx").buffer as ArrayBuffer),
        NotSupportedError,
      );
    });
  });

  describe("A README example of PSK mode", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id")
            .buffer as ArrayBuffer,
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija")
            .buffer as ArrayBuffer,
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id")
            .buffer as ArrayBuffer,
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija")
            .buffer as ArrayBuffer,
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of Auth mode", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of AuthPSK mode", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id")
            .buffer as ArrayBuffer,
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija")
            .buffer as ArrayBuffer,
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id")
            .buffer as ArrayBuffer,
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija")
            .buffer as ArrayBuffer,
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of AuthPSK mode (X25519)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id")
            .buffer as ArrayBuffer,
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija")
            .buffer as ArrayBuffer,
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id")
            .buffer as ArrayBuffer,
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija")
            .buffer as ArrayBuffer,
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of AuthPSK mode (X448)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX448HkdfSha512,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id")
            .buffer as ArrayBuffer,
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija")
            .buffer as ArrayBuffer,
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id")
            .buffer as ArrayBuffer,
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija")
            .buffer as ArrayBuffer,
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("createRecipientContext with a private key as recipientKey", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("createSenderContext with a privatekey as senderKey", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp.privateKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("seal and open (single-shot apis)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      // encrypt
      const { ct, enc } = await suite.seal(
        {
          recipientPublicKey: rkp.publicKey,
        },
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await suite.open(
        {
          recipientKey: rkp,
          enc: enc,
        },
        ct,
      );

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally (X25519)", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      // encrypt
      const { ct, enc } = await suite.seal(
        {
          recipientPublicKey: rkp.publicKey,
        },
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await suite.open(
        {
          recipientKey: rkp,
          enc: enc,
        },
        ct,
      );

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("seal empty byte string", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "");
    });
  });

  describe("deriveKeyPair with too long ikm", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      await assertRejects(
        () => suite.deriveKeyPair((new Uint8Array(8193)).buffer),
        InvalidParamError,
        "Too long ikm",
      );
    });
  });

  describe("createSenderContext with too long info", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await assertRejects(
        () =>
          suite.createSenderContext({
            info: (new Uint8Array(65537)).buffer,
            recipientPublicKey: rkp.publicKey,
          }),
        InvalidParamError,
        "Too long info",
      );
    });
  });

  describe("createSenderContext with too long psk.key", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await assertRejects(
        () =>
          suite.createSenderContext({
            psk: {
              key: (new Uint8Array(8193)).buffer as ArrayBuffer,
              id: new Uint8Array([1, 2, 3, 4]).buffer as ArrayBuffer,
            },
            recipientPublicKey: rkp.publicKey,
          }),
        InvalidParamError,
        "Too long psk.key",
      );
    });
  });

  describe("createSenderContext with short psk.key", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await assertRejects(
        () =>
          suite.createSenderContext({
            psk: {
              key: (new Uint8Array(31)).buffer as ArrayBuffer,
              id: new Uint8Array([1, 2, 3, 4]).buffer as ArrayBuffer,
            },
            recipientPublicKey: rkp.publicKey,
          }),
        InvalidParamError,
        "PSK must have at least 32 bytes",
      );
    });
  });

  describe("createSenderContext with too long psk.id", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await assertRejects(
        () =>
          suite.createSenderContext({
            psk: {
              key: new Uint8Array(32).buffer as ArrayBuffer,
              id: (new Uint8Array(8193)).buffer as ArrayBuffer,
            },
            recipientPublicKey: rkp.publicKey,
          }),
        InvalidParamError,
        "Too long psk.id",
      );
    });
  });

  describe("importKey with invalid EC(P-256) public key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexToBytes(kStr).buffer as ArrayBuffer;

      // assert
      await assertRejects(
        () => suite.importKey("raw", k),
        DeserializeError,
      );
    });
  });

  describe("importKey with invalid EC(P-256) private key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexToBytes(kStr).buffer as ArrayBuffer;

      // assert
      await assertRejects(
        () => suite.importKey("raw", k, false),
        DeserializeError,
      );
    });
  });

  describe("importKey with invalid x25519 public key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexToBytes(kStr).buffer as ArrayBuffer;

      // assert
      await assertRejects(
        () => suite.importKey("raw", k),
        DeserializeError,
      );
    });
  });

  describe("importKey with invalid x25519 private key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexToBytes(kStr).buffer as ArrayBuffer;

      // assert
      await assertRejects(
        () => suite.importKey("raw", k, false),
        DeserializeError,
      );
    });
  });

  describe("importKey with invalid x448 public key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX448HkdfSha512,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexToBytes(kStr).buffer as ArrayBuffer;

      // assert
      await assertRejects(
        () => suite.importKey("raw", k),
        DeserializeError,
      );
    });
  });

  describe("importKey with invalid x448 private key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX448HkdfSha512,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexToBytes(kStr).buffer as ArrayBuffer;

      // assert
      await assertRejects(
        () => suite.importKey("raw", k, false),
        DeserializeError,
      );
    });
  });

  describe("A README example of Oblivious HTTP", () => {
    it("should work normally", async () => {
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();

      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });
      const rkp = await suite.generateKeyPair();

      // The sender (OHTTP client) side:
      const response = te.encode("This is the response.").buffer as ArrayBuffer;
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const secretS = await sender.export(
        te.encode("message/bhttp response").buffer as ArrayBuffer,
        suite.aead.keySize,
      );

      const responseNonce = new Uint8Array(suite.aead.keySize);
      cryptoApi.getRandomValues(responseNonce);
      const saltS = concat(new Uint8Array(sender.enc), responseNonce)
        .buffer as ArrayBuffer;

      const kdfS = suite.kdf;
      const prkS = await kdfS.extract(saltS, secretS);
      const keyS = await kdfS.expand(
        prkS,
        te.encode("key").buffer as ArrayBuffer,
        suite.aead.keySize,
      );
      const nonceS = await kdfS.expand(
        prkS,
        te.encode("nonce").buffer as ArrayBuffer,
        suite.aead.nonceSize,
      );

      const aeadKeyS = await suite.aead.createEncryptionContext(keyS);
      const ct = await aeadKeyS.seal(
        nonceS,
        response,
        te.encode("").buffer as ArrayBuffer,
      );
      const encResponse = concat(responseNonce, new Uint8Array(ct));

      // The recipient (OHTTP server) side:
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      const secretR = await recipient.export(
        te.encode("message/bhttp response").buffer as ArrayBuffer,
        suite.aead.keySize,
      );

      const saltR = concat(
        new Uint8Array(sender.enc),
        encResponse.slice(0, suite.aead.keySize),
      ).buffer as ArrayBuffer;
      const kdfR = suite.kdf;
      const prkR = await kdfR.extract(saltR, secretR);
      const keyR = await kdfR.expand(
        prkR,
        te.encode("key").buffer as ArrayBuffer,
        suite.aead.keySize,
      );
      const nonceR = await kdfR.expand(
        prkR,
        te.encode("nonce").buffer as ArrayBuffer,
        suite.aead.nonceSize,
      );
      const aeadKeyR = await suite.aead.createEncryptionContext(keyR);
      const pt = await aeadKeyR.open(
        nonceR,
        encResponse.slice(suite.aead.keySize).buffer as ArrayBuffer,
        te.encode("").buffer as ArrayBuffer,
      );

      // pt === "This is the response."
      assertEquals(response, pt);
    });
  });

  describe("A README example of Oblivious HTTP (HKDF-SHA384)", () => {
    it("should work normally", async () => {
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();

      const suite = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes256Gcm,
      });
      const rkp = await suite.generateKeyPair();

      // The sender (OHTTP client) side:
      const response = te.encode("This is the response.").buffer as ArrayBuffer;
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const secretS = await sender.export(
        te.encode("message/bhttp response").buffer as ArrayBuffer,
        suite.aead.keySize,
      );

      const responseNonce = new Uint8Array(suite.aead.keySize);
      cryptoApi.getRandomValues(responseNonce);
      const saltS = concat(new Uint8Array(sender.enc), responseNonce)
        .buffer as ArrayBuffer;

      const kdfS = suite.kdf;
      const prkS = await kdfS.extract(saltS, secretS);
      const keyS = await kdfS.expand(
        prkS,
        te.encode("key").buffer as ArrayBuffer,
        suite.aead.keySize,
      );
      const nonceS = await kdfS.expand(
        prkS,
        te.encode("nonce").buffer as ArrayBuffer,
        suite.aead.nonceSize,
      );

      const aeadKeyS = await suite.aead.createEncryptionContext(keyS);
      const ct = await aeadKeyS.seal(
        nonceS,
        response,
        te.encode("").buffer as ArrayBuffer,
      );
      const encResponse = concat(responseNonce, new Uint8Array(ct));

      // The recipient (OHTTP server) side:
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      const secretR = await recipient.export(
        te.encode("message/bhttp response").buffer as ArrayBuffer,
        suite.aead.keySize,
      );

      const saltR = concat(
        new Uint8Array(sender.enc),
        encResponse.slice(0, suite.aead.keySize),
      ).buffer as ArrayBuffer;
      const kdfR = suite.kdf;
      const prkR = await kdfR.extract(saltR, secretR);
      const keyR = await kdfR.expand(
        prkR,
        te.encode("key").buffer as ArrayBuffer,
        suite.aead.keySize,
      );
      const nonceR = await kdfR.expand(
        prkR,
        te.encode("nonce").buffer as ArrayBuffer,
        suite.aead.nonceSize,
      );
      const aeadKeyR = await suite.aead.createEncryptionContext(keyR);
      const pt = await aeadKeyR.open(
        nonceR,
        encResponse.slice(suite.aead.keySize).buffer as ArrayBuffer,
        te.encode("").buffer as ArrayBuffer,
      );

      // pt === "This is the response."
      assertEquals(response, pt);
    });
  });

  describe("A README example of Oblivious HTTP (HKDF-SHA512)", () => {
    it("should work normally", async () => {
      if (isDeno()) {
        return;
      }
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();

      const suite = new CipherSuite({
        kem: Kem.DhkemP521HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes256Gcm,
      });
      const rkp = await suite.generateKeyPair();

      // The sender (OHTTP client) side:
      const response = te.encode("This is the response.").buffer as ArrayBuffer;
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const secretS = await sender.export(
        te.encode("message/bhttp response").buffer as ArrayBuffer,
        suite.aead.keySize,
      );

      const responseNonce = new Uint8Array(suite.aead.keySize);
      cryptoApi.getRandomValues(responseNonce);
      const saltS = concat(new Uint8Array(sender.enc), responseNonce)
        .buffer as ArrayBuffer;

      const kdfS = suite.kdf;
      const prkS = await kdfS.extract(saltS, secretS);
      const keyS = await kdfS.expand(
        prkS,
        te.encode("key").buffer as ArrayBuffer,
        suite.aead.keySize,
      );
      const nonceS = await kdfS.expand(
        prkS,
        te.encode("nonce").buffer as ArrayBuffer,
        suite.aead.nonceSize,
      );

      const aeadKeyS = await suite.aead.createEncryptionContext(keyS);
      const ct = await aeadKeyS.seal(
        nonceS,
        response,
        te.encode("").buffer as ArrayBuffer,
      );
      const encResponse = concat(responseNonce, new Uint8Array(ct));

      // The recipient (OHTTP server) side:
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      const secretR = await recipient.export(
        te.encode("message/bhttp response").buffer as ArrayBuffer,
        suite.aead.keySize,
      );

      const saltR = concat(
        new Uint8Array(sender.enc),
        encResponse.slice(0, suite.aead.keySize),
      ).buffer as ArrayBuffer;
      const kdfR = suite.kdf;
      const prkR = await kdfR.extract(saltR, secretR);
      const keyR = await kdfR.expand(
        prkR,
        te.encode("key").buffer as ArrayBuffer,
        suite.aead.keySize,
      );
      const nonceR = await kdfR.expand(
        prkR,
        te.encode("nonce").buffer as ArrayBuffer,
        suite.aead.nonceSize,
      );
      const aeadKeyR = await suite.aead.createEncryptionContext(keyR);
      const pt = await aeadKeyR.open(
        nonceR,
        encResponse.slice(suite.aead.keySize).buffer as ArrayBuffer,
        te.encode("").buffer as ArrayBuffer,
      );

      // pt === "This is the response."
      assertEquals(response, pt);
    });
  });
});
