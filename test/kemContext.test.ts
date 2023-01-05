import { assertEquals, assertRejects } from "testing/asserts.ts";

import { describe, it } from "testing/bdd.ts";

import { isDeno } from "../src/utils/misc.ts";
import {
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  DhkemSecp256K1HkdfSha256,
  DhkemX25519HkdfSha256,
  DhkemX448HkdfSha512,
} from "../src/kems/dhkem.ts";
import { Kem } from "../src/identifiers.ts";
import { loadCrypto, loadSubtleCrypto } from "../src/webCrypto.ts";

import * as errors from "../src/errors.ts";

describe("constructor", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const dhkemP256 = new DhkemP256HkdfSha256(api);
      assertEquals(typeof dhkemP256, "object");
      assertEquals(dhkemP256.id, Kem.DhkemP256HkdfSha256);
      assertEquals(dhkemP256.secretSize, 32);
      assertEquals(dhkemP256.encSize, 65);
      assertEquals(dhkemP256.publicKeySize, 65);
      assertEquals(dhkemP256.privateKeySize, 32);

      const dhkemP384 = new DhkemP384HkdfSha384(api);
      assertEquals(typeof dhkemP384, "object");
      assertEquals(dhkemP384.id, Kem.DhkemP384HkdfSha384);
      assertEquals(dhkemP384.secretSize, 48);
      assertEquals(dhkemP384.encSize, 97);
      assertEquals(dhkemP384.publicKeySize, 97);
      assertEquals(dhkemP384.privateKeySize, 48);

      const dhkemP521 = new DhkemP521HkdfSha512(api);
      assertEquals(typeof dhkemP521, "object");
      assertEquals(dhkemP521.id, Kem.DhkemP521HkdfSha512);
      assertEquals(dhkemP521.secretSize, 64);
      assertEquals(dhkemP521.encSize, 133);
      assertEquals(dhkemP521.publicKeySize, 133);
      assertEquals(dhkemP521.privateKeySize, 64);

      const dhkemSecp256K1 = new DhkemSecp256K1HkdfSha256(api);
      assertEquals(typeof dhkemP256, "object");
      assertEquals(dhkemSecp256K1.id, Kem.DhkemSecp256K1HkdfSha256);
      assertEquals(dhkemSecp256K1.secretSize, 32);
      assertEquals(dhkemSecp256K1.encSize, 65);
      assertEquals(dhkemSecp256K1.publicKeySize, 65);
      assertEquals(dhkemSecp256K1.privateKeySize, 32);

      const dhkemX25519 = new DhkemX25519HkdfSha256(api);
      assertEquals(typeof dhkemX25519, "object");
      assertEquals(dhkemX25519.id, Kem.DhkemX25519HkdfSha256);
      assertEquals(dhkemX25519.secretSize, 32);
      assertEquals(dhkemX25519.encSize, 32);
      assertEquals(dhkemX25519.publicKeySize, 32);
      assertEquals(dhkemX25519.privateKeySize, 32);

      const dhkemX448 = new DhkemX448HkdfSha512(api);
      assertEquals(typeof dhkemX448, "object");
      assertEquals(dhkemX448.id, Kem.DhkemX448HkdfSha512);
      assertEquals(dhkemX448.secretSize, 64);
      assertEquals(dhkemX448.encSize, 56);
      assertEquals(dhkemX448.publicKeySize, 56);
      assertEquals(dhkemX448.privateKeySize, 56);
    });
  });
});

describe("generateKeyPair", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance with DhkemP256HkdfSha256", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new DhkemP256HkdfSha256(api);
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
      const kemContext = new DhkemP384HkdfSha384(api);
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
      const kemContext = new DhkemP521HkdfSha512(api);
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

    it("should return a proper instance with DhkemSecp256K1HkdfSha256", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new DhkemSecp256K1HkdfSha256(api);
      const kp = await kemContext.generateKeyPair();
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.publicKey.usages.length, 1);
      assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemX25519HkdfSha256", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new DhkemX25519HkdfSha256(api);
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
      const kemContext = new DhkemX448HkdfSha512(api);
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
      const kemContext = new DhkemP521HkdfSha512(api);
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
      const kemContext = new DhkemP256HkdfSha256(api);
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
      const kemContext = new DhkemP384HkdfSha384(api);
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
      const kemContext = new DhkemP521HkdfSha512(api);
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

    it("should return a proper instance with DhkemSecp256K1HkdfSha256", async () => {
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();

      // assert
      const kemContext = new DhkemSecp256K1HkdfSha256(api);
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const kp = await kemContext.deriveKeyPair(ikm.buffer);
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.publicKey.usages.length, 1);
      assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });
    it("should return a proper instance with DhkemX25519HkdfSha256", async () => {
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();

      // assert
      const kemContext = new DhkemX25519HkdfSha256(api);
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
      const kemContext = new DhkemX448HkdfSha512(api);
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
      const kemContext = new DhkemP256HkdfSha256(api);
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
      const kemContext = new DhkemP256HkdfSha256(api);
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
      const kemContext = new DhkemP384HkdfSha384(api);
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
      const kemContext = new DhkemP521HkdfSha512(api);
      const kp = await kemContext.generateKeyPair();
      const bPubKey = await kemContext.serializePublicKey(kp.publicKey);
      const pubKey = await kemContext.deserializePublicKey(bPubKey);
      assertEquals(pubKey.type, "public");
      assertEquals(pubKey.extractable, true);
      assertEquals(pubKey.algorithm.name, "ECDH");
      // assertEquals(pubKey.algorithm.namedCurve, "P-521");
      assertEquals(pubKey.usages.length, 0);
    });

    it("should return a proper instance with DhkemSecp256K1HkdfSha256", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new DhkemSecp256K1HkdfSha256(api);
      const kp = await kemContext.generateKeyPair();
      const bPubKey = await kemContext.serializePublicKey(kp.publicKey);
      const pubKey = await kemContext.deserializePublicKey(bPubKey);
      assertEquals(pubKey.type, "public");
      assertEquals(pubKey.extractable, true);
      assertEquals(pubKey.algorithm.name, "ECDH");
      // assertEquals(pubKey.algorithm.namedCurve, "secp256k1");
      assertEquals(pubKey.usages.length, 1);
      assertEquals(pubKey.usages[0], "deriveBits");
    });

    it("should return a proper instance with DhkemX25519HkdfSha256", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new DhkemX25519HkdfSha256(api);
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
      const kemContext = new DhkemX448HkdfSha512(api);
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
      const ctx = new DhkemX25519HkdfSha256(api);
      const kp = await ctx.generateKeyPair();
      const kemContext = new DhkemP256HkdfSha256(api);
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
      const kemContext = new DhkemP256HkdfSha256(api);
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
