import { assertEquals, assertRejects } from "testing/asserts.ts";

import { describe, it } from "testing/bdd.ts";

import { HkdfSha256 } from "../src/kdfs/hkdfSha256.ts";
import { HkdfSha384 } from "../src/kdfs/hkdfSha384.ts";
import { HkdfSha512 } from "../src/kdfs/hkdfSha512.ts";
import { AeadId, KdfId, KemId } from "../src/identifiers.ts";
import { loadCrypto } from "../src/webCrypto.ts";
import { i2Osp } from "../src/utils/misc.ts";

const SUITE_ID_HEADER_HPKE = new Uint8Array([
  72,
  80,
  75,
  69,
  0,
  0,
  0,
  0,
  0,
  0,
]);

describe("extract/expand", () => {
  describe("HKDF-SHA256 with valid parameters", () => {
    it("should return a proper instance", async () => {
      const te = new TextEncoder();

      const cryptoApi = await loadCrypto();
      const salt = new Uint8Array(32);
      cryptoApi.getRandomValues(salt);
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP256HkdfSha256, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha256, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha256();
      await assertRejects(
        () => kdf.labeledExtract(salt.buffer, te.encode("-"), ikm),
        Error,
      );

      kdf.init(suiteId);

      const prk = await kdf.extract(salt, ikm);
      assertEquals(
        typeof await kdf.expand(prk, te.encode("key"), 16),
        "object",
      );
    });
  });

  describe("HKDF-SHA384 with valid parameters", () => {
    it("should return a proper instance", async () => {
      const te = new TextEncoder();

      const cryptoApi = await loadCrypto();
      const suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP384HkdfSha384, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha384, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha384();
      kdf.init(suiteId);

      const salt = new Uint8Array(48);
      cryptoApi.getRandomValues(salt);

      const ikm = new Uint8Array(48);
      cryptoApi.getRandomValues(ikm);

      const prk = await kdf.extract(salt, ikm);
      assertEquals(
        typeof await kdf.expand(prk, te.encode("key"), 16),
        "object",
      );
    });
  });

  describe("HKDF-SHA512 with valid parameters", () => {
    it("should return a proper instance", async () => {
      const te = new TextEncoder();

      const cryptoApi = await loadCrypto();
      const suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP521HkdfSha512, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha512, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha512();
      kdf.init(suiteId);

      const salt = new Uint8Array(64);
      cryptoApi.getRandomValues(salt);

      const ikm = new Uint8Array(64);
      cryptoApi.getRandomValues(ikm);

      const prk = await kdf.extract(salt, ikm);
      assertEquals(
        typeof await kdf.expand(prk, te.encode("key"), 16),
        "object",
      );
    });
  });

  describe("HKDF-SHA512 with over Nh length of salt.", () => {
    it("should return a proper instance", async () => {
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();
      const suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP521HkdfSha512, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha512, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha512();
      kdf.init(suiteId);

      const salt = new Uint8Array(64 + 32);
      cryptoApi.getRandomValues(salt);

      const ikm = new Uint8Array(64);
      cryptoApi.getRandomValues(ikm);

      // assert
      const prk = await kdf.extract(salt, ikm);
      assertEquals(
        typeof await kdf.expand(prk, te.encode("key"), 16),
        "object",
      );
    });
  });

  describe("HKDF-SHA384 with over Nh length of salt.", () => {
    it("should return a proper instance", async () => {
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();
      const suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP384HkdfSha384, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha384, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha384();
      kdf.init(suiteId);

      const salt = new Uint8Array(48 + 32);
      cryptoApi.getRandomValues(salt);

      const ikm = new Uint8Array(48);
      cryptoApi.getRandomValues(ikm);

      // assert
      const prk = await kdf.extract(salt, ikm);
      assertEquals(
        typeof await kdf.expand(prk, te.encode("key"), 16),
        "object",
      );
    });
  });
});
