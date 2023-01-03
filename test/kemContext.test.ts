import { assertEquals, assertRejects } from "testing/asserts.ts";

import { describe, it } from "testing/bdd.ts";

import { isDeno } from "../src/utils/misc.ts";
import { KemContext } from "../src/kemContext.ts";
import { Kem } from "../src/identifiers.ts";
import { loadCrypto, loadSubtleCrypto } from "../src/webCrypto.ts";

import * as errors from "../src/errors.ts";

describe("constructor", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      const api = await loadSubtleCrypto();

      // assert
      assertEquals(
        typeof new KemContext(api, Kem.DhkemP256HkdfSha256),
        "object",
      );
      assertEquals(
        typeof new KemContext(api, Kem.DhkemP384HkdfSha384),
        "object",
      );
      assertEquals(
        typeof new KemContext(api, Kem.DhkemP521HkdfSha512),
        "object",
      );
      assertEquals(
        typeof new KemContext(api, Kem.DhkemX25519HkdfSha256),
        "object",
      );
      assertEquals(
        typeof new KemContext(api, Kem.DhkemX448HkdfSha512),
        "object",
      );
    });
  });
});

describe("generateKeyPair", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance with DhkemP256HkdfSha256", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP256HkdfSha256);
      const kp = await kemContext.generateKeyPair();
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "P-256");
      assertEquals(kp.publicKey.usages.length, 0);
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "P-256");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemP384HkdfSha384", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP384HkdfSha384);
      const kp = await kemContext.generateKeyPair();
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "P-384");
      assertEquals(kp.publicKey.usages.length, 0);
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "P-384");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemP521HkdfSha512", async () => {
      if (isDeno()) {
        return;
      }
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP521HkdfSha512);
      const kp = await kemContext.generateKeyPair();
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "P-521");
      assertEquals(kp.publicKey.usages.length, 0);
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "P-521");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemX25519HkdfSha256", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemX25519HkdfSha256);
      const kp = await kemContext.generateKeyPair();
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "X25519");
      assertEquals(kp.publicKey.usages.length, 1);
      assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "X25519");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemX448HkdfSha512", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemX448HkdfSha512);
      const kp = await kemContext.generateKeyPair();
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "X448");
      assertEquals(kp.publicKey.usages.length, 1);
      assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "X448");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });
  });

  describe("with invalid parameters", () => {
    it("should throw NotSupportedError with DhkemP521HkdfSha512", async () => {
      if (!isDeno()) {
        return;
      }
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP521HkdfSha512);
      await assertRejects(
        () => kemContext.generateKeyPair(),
        errors.NotSupportedError,
      );
    });
  });
});

describe("deriveKeyPair", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance with DhkemP256HkdfSha256", async () => {
      if (isDeno()) {
        return;
      }
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP256HkdfSha256);
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const kp = await kemContext.deriveKeyPair(ikm.buffer);
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "P-256");
      assertEquals(kp.publicKey.usages.length, 0);
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "P-256");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemP384HkdfSha384", async () => {
      if (isDeno()) {
        return;
      }
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP384HkdfSha384);
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const kp = await kemContext.deriveKeyPair(ikm.buffer);
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "P-384");
      assertEquals(kp.publicKey.usages.length, 0);
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "P-384");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemP521HkdfSha512", async () => {
      if (isDeno()) {
        return;
      }
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP521HkdfSha512);
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const kp = await kemContext.deriveKeyPair(ikm.buffer);
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "P-521");
      assertEquals(kp.publicKey.usages.length, 0);
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "P-521");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemX25519HkdfSha256", async () => {
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemX25519HkdfSha256);
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const kp = await kemContext.deriveKeyPair(ikm.buffer);
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "X25519");
      assertEquals(kp.publicKey.usages.length, 1);
      assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "X25519");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemX448HkdfSha512", async () => {
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemX448HkdfSha512);
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const kp = await kemContext.deriveKeyPair(ikm.buffer);
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "X448");
      assertEquals(kp.publicKey.usages.length, 1);
      assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "X448");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });
  });

  describe("with invalid parameters", () => {
    it("should throw NotSupportedError with DhkemP256HkdfSha256", async () => {
      if (!isDeno()) {
        return;
      }
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP256HkdfSha256);
      await assertRejects(
        () => kemContext.deriveKeyPair(ikm.buffer),
        errors.DeriveKeyPairError,
      );
    });
  });
});

describe("serialize/deserializePublicKey", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance with DhkemP256HkdfSha256", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP256HkdfSha256);
      const kp = await kemContext.generateKeyPair();
      const bPubKey = await kemContext.serializePublicKey(kp.publicKey);
      const pubKey = await kemContext.deserializePublicKey(bPubKey);
      assertEquals(pubKey.type, "public");
      assertEquals(pubKey.extractable, true);
      assertEquals(pubKey.algorithm.name, "ECDH");
      // assertEquals(pubKey.algorithm.namedCurve, "P-256");
      assertEquals(pubKey.usages.length, 0);
    });

    it("should return a proper instance with DhkemP384HkdfSha384", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP384HkdfSha384);
      const kp = await kemContext.generateKeyPair();
      const bPubKey = await kemContext.serializePublicKey(kp.publicKey);
      const pubKey = await kemContext.deserializePublicKey(bPubKey);
      assertEquals(pubKey.type, "public");
      assertEquals(pubKey.extractable, true);
      assertEquals(pubKey.algorithm.name, "ECDH");
      // assertEquals(pubKey.algorithm.namedCurve, "P-384");
      assertEquals(pubKey.usages.length, 0);
    });

    it("should return a proper instance with DhkemP521HkdfSha512", async () => {
      if (isDeno()) {
        return;
      }
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP521HkdfSha512);
      const kp = await kemContext.generateKeyPair();
      const bPubKey = await kemContext.serializePublicKey(kp.publicKey);
      const pubKey = await kemContext.deserializePublicKey(bPubKey);
      assertEquals(pubKey.type, "public");
      assertEquals(pubKey.extractable, true);
      assertEquals(pubKey.algorithm.name, "ECDH");
      // assertEquals(pubKey.algorithm.namedCurve, "P-521");
      assertEquals(pubKey.usages.length, 0);
    });

    it("should return a proper instance with DhkemX25519HkdfSha256", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemX25519HkdfSha256);
      const kp = await kemContext.generateKeyPair();
      const bPubKey = await kemContext.serializePublicKey(kp.publicKey);
      const pubKey = await kemContext.deserializePublicKey(bPubKey);
      assertEquals(pubKey.type, "public");
      assertEquals(pubKey.extractable, true);
      assertEquals(pubKey.algorithm.name, "X25519");
      assertEquals(pubKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemX448HkdfSha512", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemX448HkdfSha512);
      const kp = await kemContext.generateKeyPair();
      const bPubKey = await kemContext.serializePublicKey(kp.publicKey);
      const pubKey = await kemContext.deserializePublicKey(bPubKey);
      assertEquals(pubKey.type, "public");
      assertEquals(pubKey.extractable, true);
      assertEquals(pubKey.algorithm.name, "X448");
      assertEquals(pubKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });
  });

  describe("with invalid parameters", () => {
    it("should throw SerializeError on serializePublicKey with a public key for X25519", async () => {
      if (!isDeno()) {
        return;
      }
      const api = await loadSubtleCrypto();

      // assert
      const ctx = new KemContext(api, Kem.DhkemX25519HkdfSha256);
      const kp = await ctx.generateKeyPair();
      const kemContext = new KemContext(api, Kem.DhkemP256HkdfSha256);
      await assertRejects(
        () => kemContext.serializePublicKey(kp.publicKey),
        errors.SerializeError,
      );
    });

    it("should throw DeserializeError on deserializePublicKey with DhkemP256HkdfSha256", async () => {
      if (!isDeno()) {
        return;
      }
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new KemContext(api, Kem.DhkemP256HkdfSha256);
      // const kp = await kemContext.generateKeyPair();
      // await assertRejects(
      //   () => kemContext.serializePublicKey(kp.publicKey),
      //   errors.SerializeError,
      // );
      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(32);
      cryptoApi.getRandomValues(rawKey);
      await assertRejects(
        () => kemContext.deserializePublicKey(rawKey.buffer),
        errors.DeserializeError,
      );
    });
  });
});
