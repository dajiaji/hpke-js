import { assertEquals, assertRejects } from "testing/asserts.ts";
import { describe, it } from "testing/bdd.ts";

import {
  AeadId,
  CipherSuite,
  KdfId,
  KemId,
} from "https://deno.land/x/hpke/mod.ts";

import { DhkemSecp256k1HkdfSha256 } from "../src/dhkemSecp256k1HkdfSha256.ts";

const isBrowser = () => typeof window !== "undefined";

const isCloudflareWorkers = () => typeof caches !== "undefined";

function hexStringToBytes(v: string): Uint8Array {
  if (v.length === 0) {
    return new Uint8Array([]);
  }
  const res = v.match(/[\da-f]{2}/gi);
  if (res == null) {
    throw new Error("hexStringToBytes: not hex string");
  }
  return new Uint8Array(res.map(function (h) {
    return parseInt(h, 16);
  }));
}

async function loadCrypto(): Promise<Crypto> {
  if (isBrowser() || isCloudflareWorkers()) {
    if (globalThis.crypto !== undefined) {
      return globalThis.crypto;
    }
    // jsdom
  }

  try {
    const { webcrypto } = await import("crypto"); // node:crypto
    return (webcrypto as unknown as Crypto);
  } catch (_e: unknown) {
    throw new Error("Web Cryptograph API not supported");
  }
}

async function loadSubtleCrypto(): Promise<SubtleCrypto> {
  if (isBrowser() || isCloudflareWorkers()) {
    if (globalThis.crypto !== undefined) {
      return globalThis.crypto.subtle;
    }
    // jsdom
  }

  try {
    const { webcrypto } = await import("crypto"); // node:crypto
    return (webcrypto as unknown as Crypto).subtle;
  } catch (_e: unknown) {
    throw new Error("Web Cryptograph API not supported");
  }
}

describe("DhkemP256k1Hkdf256", () => {
  describe("with valid parameters", () => {
    it("should have a correct KEM object", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const dhkemSecp256k1 = new DhkemSecp256k1HkdfSha256();
      dhkemSecp256k1.init(api);
      assertEquals(typeof dhkemSecp256k1, "object");
      assertEquals(dhkemSecp256k1.id, KemId.DhkemSecp256K1HkdfSha256);
      assertEquals(dhkemSecp256k1.secretSize, 32);
      assertEquals(dhkemSecp256k1.encSize, 65);
      assertEquals(dhkemSecp256k1.publicKeySize, 65);
      assertEquals(dhkemSecp256k1.privateKeySize, 32);
    });
  });
});

describe("generateKeyPair", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new DhkemSecp256k1HkdfSha256();
      kemContext.init(api);
      const kp = await kemContext.generateKeyPair();
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.publicKey.usages.length, 0);
      // assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });
  });
});

describe("deriveKeyPair", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      const api = await loadSubtleCrypto();
      const cryptoApi = await loadCrypto();

      // assert
      const kemContext = new DhkemSecp256k1HkdfSha256();
      kemContext.init(api);
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const kp = await kemContext.deriveKeyPair(ikm.buffer);
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.publicKey.usages.length, 0);
      // assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });
  });
});

describe("serialize/deserializePublicKey", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance with DhkemSecp256k1HkdfSha256", async () => {
      const api = await loadSubtleCrypto();

      // assert
      const kemContext = new DhkemSecp256k1HkdfSha256();
      kemContext.init(api);
      const kp = await kemContext.generateKeyPair();
      const bPubKey = await kemContext.serializePublicKey(kp.publicKey);
      const pubKey = await kemContext.deserializePublicKey(bPubKey);
      assertEquals(pubKey.type, "public");
      assertEquals(pubKey.extractable, true);
      assertEquals(pubKey.algorithm.name, "ECDH");
      // assertEquals(pubKey.algorithm.namedCurve, "secp256k1");
      assertEquals(pubKey.usages.length, 0);
      // assertEquals(pubKey.usages[0], "deriveBits");
    });
  });
});

describe("importKey", () => {
  describe("with valid parameters", () => {
    it("should return a valid private key for DhkemSecp256k1HkdfSha256 from raw key", async () => {
      const api = await loadSubtleCrypto();
      const kemContext = new DhkemSecp256k1HkdfSha256();
      kemContext.init(api);

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(32);
      cryptoApi.getRandomValues(rawKey);
      const privKey = await kemContext.importKey("raw", rawKey, false);

      // assert
      assertEquals(privKey.usages.length, 1);
      assertEquals(privKey.usages[0], "deriveBits");
    });

    it("should return a valid public key for DhkemSecp256k1HkdfSha256 from raw key", async () => {
      const api = await loadSubtleCrypto();
      const kemContext = new DhkemSecp256k1HkdfSha256();
      kemContext.init(api);

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(33);
      rawKey[0] = hexStringToBytes("04")[0];
      cryptoApi.getRandomValues(rawKey);
      const privKey = await kemContext.importKey("raw", rawKey, true);

      // assert
      assertEquals(privKey.usages.length, 0);
      // assertEquals(privKey.usages[0], "deriveBits");
    });
  });

  describe("with invalid parameters", () => {
    it("should throw DeserializeError with invalid DhkemSecp256k1HkdfSha256 private key", async () => {
      const api = await loadSubtleCrypto();
      const kemContext = new DhkemSecp256k1HkdfSha256();
      kemContext.init(api);

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(33);
      cryptoApi.getRandomValues(rawKey);

      // assert
      await assertRejects(
        () => kemContext.importKey("raw", rawKey, false),
        Error,
      );
    });

    it("should throw DeserializeError with invalid DhkemSecp256k1HkdfSha256 public key", async () => {
      const api = await loadSubtleCrypto();
      const kemContext = new DhkemSecp256k1HkdfSha256();
      kemContext.init(api);

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(32);
      cryptoApi.getRandomValues(rawKey);

      // assert
      await assertRejects(
        () => kemContext.importKey("raw", rawKey, true),
        Error,
      );
    });
  });
});

describe("CipherSuite", () => {
  describe("constructor with DhkemP256HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should have a correct ciphersuite", async () => {
      const suite: CipherSuite = new CipherSuite({
        kem: new DhkemSecp256k1HkdfSha256(),
        kdf: KdfId.HkdfSha256,
        aead: AeadId.ExportOnly,
      });
      const kem = await suite.kemContext();
      assertEquals(kem.secretSize, 32);
      assertEquals(kem.encSize, 65);
      assertEquals(kem.publicKeySize, 65);
      assertEquals(kem.privateKeySize, 32);

      // assert
      assertEquals(suite.kem, KemId.DhkemSecp256K1HkdfSha256);
      assertEquals(suite.kem, 0x0013);
      assertEquals(suite.kdf, KdfId.HkdfSha256);
      assertEquals(suite.kdf, 0x0001);
      assertEquals(suite.aead, AeadId.ExportOnly);
      assertEquals(suite.aead, 0xFFFF);
    });
  });

  describe("A README example of Base mode (DhkemSecp256k1HkdfSha256/KdfId.HkdfSha256)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemSecp256k1HkdfSha256(),
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
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
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });
});
