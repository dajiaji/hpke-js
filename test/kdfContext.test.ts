import { assertEquals, assertRejects } from "testing/asserts.ts";

import { describe, it } from "testing/bdd.ts";

import { KdfContext } from "../src/kdfContext.ts";
import { Aead, Kdf, Kem } from "../src/identifiers.ts";
import { loadCrypto, loadSubtleCrypto } from "../src/webCrypto.ts";

import * as errors from "../src/errors.ts";

describe("extract/expand", () => {
  describe("HKDF-SHA256 with valid parameters", () => {
    it("should return a proper instance", async () => {
      const te = new TextEncoder();

      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const salt = new Uint8Array(32);
      cryptoApi.getRandomValues(salt);

      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);

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

      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

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

      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP521HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes128Gcm,
      });

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
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP521HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes128Gcm,
      });

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

  describe("HKDF-SHA384 with unsupported salt length", () => {
    it("should return a proper instance", async () => {
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const salt = new Uint8Array(48 + 32);
      cryptoApi.getRandomValues(salt);

      const ikm = new Uint8Array(48);
      cryptoApi.getRandomValues(ikm);

      // assert
      await assertRejects(
        () => kdf.extract(salt, ikm),
        errors.NotSupportedError,
      );
    });
  });
});
