import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { AeadId, CipherSuite, KdfId, KemId } from "../mod.ts";
import { Aes128Gcm } from "../core/src/aeads/aesGcm.ts";
import * as errors from "../core/src/errors.ts";
import { DhkemP256HkdfSha256 } from "../src/kems/dhkemP256.ts";
import { DhkemP384HkdfSha384 } from "../src/kems/dhkemP384.ts";
import { DhkemP521HkdfSha512 } from "../src/kems/dhkemP521.ts";
import { HkdfSha384 } from "../src/kdfs/hkdfSha384.ts";
import { isDeno } from "../core/src/utils/misc.ts";

import { DhkemX25519HkdfSha256 } from "../x/dhkem-x25519/src/dhkemX25519.ts";
import { HkdfSha256 } from "../x/dhkem-x25519/src/hkdfSha256.ts";

import { DhkemX448HkdfSha512 } from "../x/dhkem-x448/src/dhkemX448.ts";
import { HkdfSha512 } from "../x/dhkem-x448/src/hkdfSha512.ts";

import { concat, loadCrypto } from "../core/test/utils.ts";

describe("README examples", () => {
  describe("Base mode with DhkemP256HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should work normally with ids", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), errors.NotSupportedError);
      await assertRejects(() => sender.open(ct), errors.NotSupportedError);
    });

    it("should work normally with instances", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), errors.NotSupportedError);
      await assertRejects(() => sender.open(ct), errors.NotSupportedError);
    });

    it("should work normally with importKey('jwk')", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const jwkPkR = {
        kty: "EC",
        crv: "P-256",
        kid: "P-256-01",
        x: "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
        y: "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
        key_ops: [],
      };
      const pkR = await suite.kem.importKey("jwk", jwkPkR, true);

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
      const skR = await suite.kem.importKey("jwk", jwkSkR, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: skR,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), errors.NotSupportedError);
      await assertRejects(() => sender.open(ct), errors.NotSupportedError);
    });
  });

  describe("Base mode with DhkemP384HkdfSha384/HkdfSha384/Aes128Gcm.", () => {
    it("should work normally with ids", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemP384HkdfSha384,
        kdf: KdfId.HkdfSha384,
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with instances", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP384HkdfSha384(),
        kdf: new HkdfSha384(),
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with importKey('jwk')", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemP384HkdfSha384,
        kdf: KdfId.HkdfSha384,
        aead: AeadId.Aes128Gcm,
      });

      const jwkPkR = {
        kty: "EC",
        crv: "P-384",
        kid: "P-384-01",
        x: "_XyN9woHaS0mPimSW-etwJMEDSzxIMjp4PjezavU8SHJoClz1bQrcmPb1ZJxHxhI",
        y: "GCNfc32p9sRotx7u2oDGJ3Eqz6q5zPHLdizNn83oRsUTN31eCWfGLHWRury3xF50",
        key_ops: [],
      };
      const pkR = await suite.kem.importKey("jwk", jwkPkR, true);

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
      const skR = await suite.kem.importKey("jwk", jwkSkR, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: skR,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), errors.NotSupportedError);
      await assertRejects(() => sender.open(ct), errors.NotSupportedError);
    });
  });

  describe("Base mode with DhkemP521HkdfSha512/HkdfSha512/Aes128Gcm", () => {
    it("should work normally with ids", async () => {
      if (isDeno()) {
        return;
      }

      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemP521HkdfSha512,
        kdf: KdfId.HkdfSha512,
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with instances", async () => {
      if (isDeno()) {
        return;
      }

      // setup
      const suite = new CipherSuite({
        kem: new DhkemP521HkdfSha512(),
        kdf: new HkdfSha512(),
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
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
        kem: KemId.DhkemP521HkdfSha512,
        kdf: KdfId.HkdfSha512,
        aead: AeadId.Aes128Gcm,
      });

      const jwkPkR = {
        kty: "EC",
        crv: "P-521",
        kid: "P-521-01",
        x: "APkZitSJMJUMB-iPCt47sWu_CrnUHg6IAR4qjmHON-2u41Rjg6DNOS0LZYJJt-AVH5NgGVi8ElIfjo71b9HXCTOc",
        y: "ASx-Cb--149HJ-e1KlSaY-1BOhwOdcTkxSt8BGbW7_hnGfzHsoXM3ywwNcp1Yad-FHUKwmCyMelMQEn2Rh4V2l3I",
        key_ops: [],
      };
      const pkR = await suite.kem.importKey("jwk", jwkPkR, true);

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
      const skR = await suite.kem.importKey("jwk", jwkSkR, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: skR,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), errors.NotSupportedError);
      await assertRejects(() => sender.open(ct), errors.NotSupportedError);
    });
  });

  describe("Base mode with DhkemX25519HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should work normally with ids", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with instances", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with importKey('jwk')", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const jwkPkR = {
        kty: "OKP",
        crv: "X25519",
        kid: "X25519-01",
        x: "y3wJq3uXPHeoCO4FubvTc7VcBuqpvUrSvU6ZMbHDTCI",
        key_ops: [],
      };
      const pkR = await suite.kem.importKey("jwk", jwkPkR, true);

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
      const skR = await suite.kem.importKey("jwk", jwkSkR, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: skR,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), errors.NotSupportedError);
      await assertRejects(() => sender.open(ct), errors.NotSupportedError);
    });
  });

  describe("Base mode with DhkemX448HkdfSha256/HkdfSha512/Aes256Gcm)", () => {
    it("should work normally with ids", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemX448HkdfSha512,
        kdf: KdfId.HkdfSha512,
        aead: AeadId.Aes256Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with instances", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemX448HkdfSha512(),
        kdf: new HkdfSha512(),
        aead: AeadId.Aes256Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with importKey('jwk')", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemX448HkdfSha512,
        kdf: KdfId.HkdfSha512,
        aead: AeadId.Aes256Gcm,
      });

      const jwkPkR = {
        kty: "OKP",
        crv: "X448",
        kid: "X448-01",
        x: "IkLmc0klvEMXYneHMKAB6ePohryAwAPVe2pRSffIDY6NrjeYNWVX5J-fG4NV2OoU77C88A0mvxI",
        key_ops: [],
      };
      const pkR = await suite.kem.importKey("jwk", jwkPkR, true);

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
      const skR = await suite.kem.importKey("jwk", jwkSkR, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: skR,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), errors.NotSupportedError);
      await assertRejects(() => sender.open(ct), errors.NotSupportedError);
    });
  });

  describe("Base mode with DhkemP256HkdfSha256/HkdfSha256/ExportOnly", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.ExportOnly,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      const te = new TextEncoder();

      // export
      const pskS = sender.export(te.encode("jugemujugemu"), 32);
      const pskR = recipient.export(te.encode("jugemujugemu"), 32);
      assertEquals(pskR, pskS);

      // other functions are disabled.
      await assertRejects(
        () => sender.seal(te.encode("my-secret-message")),
        errors.NotSupportedError,
      );
      await assertRejects(
        () => sender.open(te.encode("xxxxxxxxxxxxxxxxx")),
        errors.NotSupportedError,
      );
    });
  });

  describe("Base mode with DhkemX25519HkdfSha256/HkdfSha256/ExportOnly", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.ExportOnly,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      const te = new TextEncoder();

      // export
      const pskS = sender.export(te.encode("jugemujugemu"), 32);
      const pskR = recipient.export(te.encode("jugemujugemu"), 32);
      assertEquals(pskR, pskS);

      // other functions are disabled.
      await assertRejects(
        () => sender.seal(te.encode("my-secret-message")),
        errors.NotSupportedError,
      );
      await assertRejects(
        () => sender.open(te.encode("xxxxxxxxxxxxxxxxx")),
        errors.NotSupportedError,
      );
    });
  });

  describe("PSK mode", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("Auth mode", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();
      const skp = await suite.kem.generateKeyPair();

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
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("AuthPSK mode with DhkemP256HkdfSha256", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();
      const skp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("AuthPSK mode with DhkemX25519HkdfSha256", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();
      const skp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("AuthPSK mode with DhkemX448HkdfSha512", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemX448HkdfSha512,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.kem.generateKeyPair();
      const skp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("Bidirectional Encryption with DhkemP256HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should work normally", async () => {
      const te = new TextEncoder();

      // A recipient generates a keypair.
      const recipient = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });
      const rkp = await recipient.kem.generateKeyPair();

      // A sender generates an encapusulated key (enc) with the recipient's public key.
      const sender = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });
      const ctxS = await sender.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      // The recipient decapsulates the enc with the recipient's private key.
      const ctxR = await recipient.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: ctxS.enc,
      });

      // The recipient encrypts a plaintext.
      const keyR = await ctxR.export(
        te.encode("response key"),
        recipient.aead.keySize,
      );
      const nonceR = await ctxR.export(
        te.encode("response nonce"),
        recipient.aead.nonceSize,
      );
      const aeadCtxR = await recipient.aead.createEncryptionContext(keyR);
      const ct = await aeadCtxR.seal(
        nonceR,
        te.encode("Hello world!"),
        te.encode("jugemu-jugemu"),
      );

      // The sender decrypts the ciphertext.
      const keyS = await ctxS.export(
        te.encode("response key"),
        sender.aead.keySize,
      );
      const nonceS = await ctxS.export(
        te.encode("response nonce"),
        sender.aead.nonceSize,
      );
      const aeadCtxS = await sender.aead.createEncryptionContext(keyS);
      const pt = await aeadCtxS.open(nonceS, ct, te.encode("jugemu-jugemu"));

      // pt === "Hello world!"
      assertEquals(te.encode("Hello world!"), new Uint8Array(pt));
    });
  });

  describe("Oblivious HTTP with DhkemP256HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should work normally", async () => {
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();

      const suite = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });
      const rkp = await suite.kem.generateKeyPair();

      // The sender (OHTTP client) side:
      const response = te.encode("This is the response.");
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const secretS = await sender.export(
        te.encode("message/bhttp response"),
        suite.aead.keySize,
      );

      const responseNonce = new Uint8Array(suite.aead.keySize);
      cryptoApi.getRandomValues(responseNonce);
      const saltS = concat(new Uint8Array(sender.enc), responseNonce);

      const prkS = await suite.kdf.extract(saltS, new Uint8Array(secretS));
      const keyS = await suite.kdf.expand(
        prkS,
        te.encode("key"),
        suite.aead.keySize,
      );
      const nonceS = await suite.kdf.expand(
        prkS,
        te.encode("nonce"),
        suite.aead.nonceSize,
      );

      const aeadKeyS = await suite.aead.createEncryptionContext(keyS);
      const ct = await aeadKeyS.seal(nonceS, response, te.encode(""));
      const encResponse = concat(responseNonce, new Uint8Array(ct));

      // The recipient (OHTTP server) side:
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      const secretR = await recipient.export(
        te.encode("message/bhttp response"),
        suite.aead.keySize,
      );

      const saltR = concat(
        new Uint8Array(sender.enc),
        encResponse.slice(0, suite.aead.keySize),
      );
      const prkR = await suite.kdf.extract(
        saltR,
        new Uint8Array(secretR),
      );
      const keyR = await suite.kdf.expand(
        prkR,
        te.encode("key"),
        suite.aead.keySize,
      );
      const nonceR = await suite.kdf.expand(
        prkR,
        te.encode("nonce"),
        suite.aead.nonceSize,
      );
      const aeadKeyR = await suite.aead.createEncryptionContext(keyR);
      const pt = await aeadKeyR.open(
        nonceR,
        encResponse.slice(suite.aead.keySize),
        te.encode(""),
      );

      // pt === "This is the response."
      assertEquals(response, new Uint8Array(pt));
    });
  });

  describe("Oblivious HTTP with DhkemP384HkdfSha384/HkdfSha384/Aes256Gcm", () => {
    it("should work normally", async () => {
      if (isDeno()) {
        return;
      }
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();

      const suite = new CipherSuite({
        kem: KemId.DhkemP384HkdfSha384,
        kdf: KdfId.HkdfSha384,
        aead: AeadId.Aes256Gcm,
      });
      const rkp = await suite.kem.generateKeyPair();

      // The sender (OHTTP client) side:
      const response = te.encode("This is the response.");
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const secretS = await sender.export(
        te.encode("message/bhttp response"),
        suite.aead.keySize,
      );

      const responseNonce = new Uint8Array(suite.aead.keySize);
      cryptoApi.getRandomValues(responseNonce);
      const saltS = concat(new Uint8Array(sender.enc), responseNonce);

      const prkS = await suite.kdf.extract(saltS, new Uint8Array(secretS));
      const keyS = await suite.kdf.expand(
        prkS,
        te.encode("key"),
        suite.aead.keySize,
      );
      const nonceS = await suite.kdf.expand(
        prkS,
        te.encode("nonce"),
        suite.aead.nonceSize,
      );

      const aeadKeyS = await suite.aead.createEncryptionContext(keyS);
      const ct = await aeadKeyS.seal(nonceS, response, te.encode(""));
      const encResponse = concat(responseNonce, new Uint8Array(ct));

      // The recipient (OHTTP server) side:
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      const secretR = await recipient.export(
        te.encode("message/bhttp response"),
        suite.aead.keySize,
      );

      const saltR = concat(
        new Uint8Array(sender.enc),
        encResponse.slice(0, suite.aead.keySize),
      );
      const prkR = await suite.kdf.extract(
        saltR,
        new Uint8Array(secretR),
      );
      const keyR = await suite.kdf.expand(
        prkR,
        te.encode("key"),
        suite.aead.keySize,
      );
      const nonceR = await suite.kdf.expand(
        prkR,
        te.encode("nonce"),
        suite.aead.nonceSize,
      );
      const aeadKeyR = await suite.aead.createEncryptionContext(keyR);
      const pt = await aeadKeyR.open(
        nonceR,
        encResponse.slice(suite.aead.keySize),
        te.encode(""),
      );

      // pt === "This is the response."
      assertEquals(response, new Uint8Array(pt));
    });
  });

  describe("Oblivious HTTP with DhkemP521HkdfSha512/HkdfSha512/Aes256Gcm", () => {
    it("should work normally", async () => {
      if (isDeno()) {
        return;
      }
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();

      const suite = new CipherSuite({
        kem: KemId.DhkemP521HkdfSha512,
        kdf: KdfId.HkdfSha512,
        aead: AeadId.Aes256Gcm,
      });
      const rkp = await suite.kem.generateKeyPair();

      // The sender (OHTTP client) side:
      const response = te.encode("This is the response.");
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const secretS = await sender.export(
        te.encode("message/bhttp response"),
        suite.aead.keySize,
      );

      const responseNonce = new Uint8Array(suite.aead.keySize);
      cryptoApi.getRandomValues(responseNonce);
      const saltS = concat(new Uint8Array(sender.enc), responseNonce);

      const prkS = await suite.kdf.extract(saltS, new Uint8Array(secretS));
      const keyS = await suite.kdf.expand(
        prkS,
        te.encode("key"),
        suite.aead.keySize,
      );
      const nonceS = await suite.kdf.expand(
        prkS,
        te.encode("nonce"),
        suite.aead.nonceSize,
      );

      const aeadKeyS = await suite.aead.createEncryptionContext(keyS);
      const ct = await aeadKeyS.seal(nonceS, response, te.encode(""));
      const encResponse = concat(responseNonce, new Uint8Array(ct));

      // The recipient (OHTTP server) side:
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      const secretR = await recipient.export(
        te.encode("message/bhttp response"),
        suite.aead.keySize,
      );

      const saltR = concat(
        new Uint8Array(sender.enc),
        encResponse.slice(0, suite.aead.keySize),
      );
      const prkR = await suite.kdf.extract(
        saltR,
        new Uint8Array(secretR),
      );
      const keyR = await suite.kdf.expand(
        prkR,
        te.encode("key"),
        suite.aead.keySize,
      );
      const nonceR = await suite.kdf.expand(
        prkR,
        te.encode("nonce"),
        suite.aead.nonceSize,
      );
      const aeadKeyR = await suite.aead.createEncryptionContext(keyR);
      const pt = await aeadKeyR.open(
        nonceR,
        encResponse.slice(suite.aead.keySize),
        te.encode(""),
      );

      // pt === "This is the response."
      assertEquals(response, new Uint8Array(pt));
    });
  });
});
