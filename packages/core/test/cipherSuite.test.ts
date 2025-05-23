import { assertEquals, assertRejects, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { hexToBytes, isDeno, isDenoV1 } from "@hpke/common";

import {
  AeadId,
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  DeserializeError,
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  DhkemX25519HkdfSha256,
  ExportOnly,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
  InvalidParamError,
  KdfId,
  KemId,
} from "../mod.ts";

describe("constructor", () => {
  // RFC9180 A.1.
  describe("with DhkemX25519HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should have ciphersuites", async () => {
      if (isDeno()) {
        return;
      }
      const suite = new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      // assert
      assertEquals(suite.kem.id, KemId.DhkemX25519HkdfSha256);
      assertEquals(suite.kem.id, 0x0020);
      assertEquals(suite.kdf.id, KdfId.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, AeadId.Aes128Gcm);
      assertEquals(suite.aead.id, 0x0001);

      const rkp = await suite.kem.generateKeyPair();
      assertEquals(rkp.publicKey.type, "public");
      assertEquals(rkp.publicKey.extractable, true);
      assertEquals(rkp.publicKey.algorithm.name, "X25519");
      assertEquals(rkp.publicKey.usages.length, 0);
      assertEquals(rkp.privateKey.type, "private");
      assertEquals(rkp.privateKey.extractable, true);
      assertEquals(rkp.privateKey.algorithm.name, "X25519");
      assertEquals(rkp.privateKey.usages.length, 1);
      assertEquals(rkp.privateKey.usages[0], "deriveBits");
    });
  });

  describe("with DhkemP384HkdfSha384/HkdfSha384/Aes128Gcm", () => {
    it("should have a correct ciphersuite", () => {
      const suite = new CipherSuite({
        kem: new DhkemP384HkdfSha384(),
        kdf: new HkdfSha384(),
        aead: new Aes128Gcm(),
      });

      // assert
      assertEquals(suite.kem.id, KemId.DhkemP384HkdfSha384);
      assertEquals(suite.kem.id, 0x0011);
      assertEquals(suite.kem.secretSize, 48);
      assertEquals(suite.kem.encSize, 97);
      assertEquals(suite.kem.publicKeySize, 97);
      assertEquals(suite.kem.privateKeySize, 48);
      assertEquals(suite.aead.keySize, 16);
      assertEquals(suite.aead.nonceSize, 12);
      assertEquals(suite.aead.tagSize, 16);
      assertEquals(suite.kdf.id, KdfId.HkdfSha384);
      assertEquals(suite.kdf.id, 0x0002);
      assertEquals(suite.aead.id, AeadId.Aes128Gcm);
      assertEquals(suite.aead.id, 0x0001);
    });
  });

  // RFC9180 A.2.
  describe("with DhkemP384HkdfSha384/HkdfSha384/Aes256Gcm", () => {
    it("should have a correct ciphersuite", () => {
      const suite = new CipherSuite({
        kem: new DhkemP384HkdfSha384(),
        kdf: new HkdfSha384(),
        aead: new Aes256Gcm(),
      });

      // assert
      assertEquals(suite.kem.id, KemId.DhkemP384HkdfSha384);
      assertEquals(suite.kem.id, 0x0011);
      assertEquals(suite.kdf.id, KdfId.HkdfSha384);
      assertEquals(suite.kdf.id, 0x0002);
      assertEquals(suite.aead.id, AeadId.Aes256Gcm);
      assertEquals(suite.aead.id, 0x0002);
    });
  });

  describe("with DhkemP256HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should have ciphersuites", () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      // assert
      assertEquals(suite.kem.id, KemId.DhkemP256HkdfSha256);
      assertEquals(suite.kem.id, 0x0010);
      assertEquals(suite.kdf.id, KdfId.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, AeadId.Aes128Gcm);
      assertEquals(suite.aead.id, 0x0001);
    });
  });

  describe("with DhkemP256HkdfSha256/HkdfSha512/Aes128Gcm", () => {
    it("should have ciphersuites", () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha512(),
        aead: new Aes128Gcm(),
      });

      // assert
      assertEquals(suite.kem.id, KemId.DhkemP256HkdfSha256);
      assertEquals(suite.kem.id, 0x0010);
      assertEquals(suite.kdf.id, KdfId.HkdfSha512);
      assertEquals(suite.kdf.id, 0x0003);
      assertEquals(suite.aead.id, AeadId.Aes128Gcm);
      assertEquals(suite.aead.id, 0x0001);
    });
  });

  describe("with DhkemP256HkdfSha256/HkdfSha256/Aes256Gcm", () => {
    it("should have ciphersuites", () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes256Gcm(),
      });

      // assert
      assertEquals(suite.kem.id, KemId.DhkemP256HkdfSha256);
      assertEquals(suite.kem.id, 0x0010);
      assertEquals(suite.kdf.id, KdfId.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, AeadId.Aes256Gcm);
      assertEquals(suite.aead.id, 0x0002);
    });
  });

  // RFC9180 A.6.
  describe("with DhkemP521HkdfSha512/HkdfSha512/Aes256Gcm", () => {
    it("should have ciphersuites", () => {
      const suite = new CipherSuite({
        kem: new DhkemP521HkdfSha512(),
        kdf: new HkdfSha512(),
        aead: new Aes256Gcm(),
      });

      // assert
      assertEquals(suite.kem.id, KemId.DhkemP521HkdfSha512);
      assertEquals(suite.kem.id, 0x0012);
      assertEquals(suite.kdf.id, KdfId.HkdfSha512);
      assertEquals(suite.kdf.id, 0x0003);
      assertEquals(suite.aead.id, AeadId.Aes256Gcm);
      assertEquals(suite.aead.id, 0x0002);
    });
  });

  // RFC9180 A.7.
  describe("with DhkemP256HkdfSha256/HkdfSha256/ExportOnly", () => {
    it("should have ciphersuites", () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new ExportOnly(),
      });

      // assert
      assertEquals(suite.kem.id, KemId.DhkemP256HkdfSha256);
      assertEquals(suite.kem.id, 0x0010);
      assertEquals(suite.kdf.id, KdfId.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, AeadId.ExportOnly);
      assertEquals(suite.aead.id, 0xFFFF);
    });
  });

  describe("with KemId", () => {
    it("should throw InvalidParamError", async () => {
      // assert
      await assertThrows(
        () =>
          new CipherSuite({
            kem: KemId.DhkemSecp256k1HkdfSha256,
            kdf: new HkdfSha256(),
            aead: new ExportOnly(),
          }),
        InvalidParamError,
        "KemId cannot be used",
      );
    });
  });

  describe("with KdfId", () => {
    it("should throw InvalidParamError", async () => {
      // assert
      await assertThrows(
        () =>
          new CipherSuite({
            kem: new DhkemP256HkdfSha256(),
            kdf: KdfId.HkdfSha256,
            aead: new ExportOnly(),
          }),
        InvalidParamError,
        "KdfId cannot be used",
      );
    });
  });

  describe("with AeadId", () => {
    it("should throw InvalidParamError", async () => {
      // assert
      await assertThrows(
        () =>
          new CipherSuite({
            kem: new DhkemP256HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: AeadId.ExportOnly,
          }),
        InvalidParamError,
        "AeadId cannot be used",
      );
    });
  });
});

describe("createRecipientContext", () => {
  describe("with a private key as recipientKey", () => {
    it("should work normally", async () => {
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

  describe("with too long info", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

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
});

describe("createSenderContext", () => {
  describe("with a privatekey as senderKey", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();
      const skp = await suite.kem.generateKeyPair();

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

  describe("with too long psk.key", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

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

  describe("with short psk.key", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

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

  describe("with too long psk.id", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

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
});

describe("seal/open", () => {
  describe("with DhkemP256HkdfSha256", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

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

  // describe("with DhkemX25519HkdfSha256", () => {
  //   it("should work normally.", async () => {
  //     // setup
  //     const suite = new CipherSuite({
  //       kem: new DhkemX25519HkdfSha256(),
  //       kdf: new HkdfSha256(),
  //       aead: new Aes128Gcm(),
  //     });

  //     const rkp = await suite.kem.generateKeyPair();

  //     // encrypt
  //     const { ct, enc } = await suite.seal(
  //       {
  //         recipientPublicKey: rkp.publicKey,
  //       },
  //       new TextEncoder().encode("my-secret-message"),
  //     );

  //     // decrypt
  //     const pt = await suite.open(
  //       {
  //         recipientKey: rkp,
  //         enc: enc,
  //       },
  //       ct,
  //     );

  //     // assert
  //     assertEquals(new TextDecoder().decode(pt), "my-secret-message");
  //   });
  // });

  describe("seal with empty byte string", () => {
    it("should work normally", async () => {
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
        new TextEncoder().encode("").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "");
    });
  });
});

describe("deriveKeyPair", () => {
  // describe("with official test-vector for DhkemX25519HkdfSha256.", () => {
  //   it("should derive a proper key pair.", async () => {
  //     const ikmR = hexToBytes(
  //       "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
  //     );
  //     const ikmE = hexToBytes(
  //       "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
  //     );
  //     const pkRm = hexToBytes(
  //       "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
  //     );
  //     const pkEm = hexToBytes(
  //       "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
  //     );

  //     const suite = new CipherSuite({
  //       kem: new DhkemX25519HkdfSha256(),
  //       kdf: new HkdfSha256(),
  //       aead: new Aes128Gcm(),
  //     });
  //     const derivedR = await suite.kem.deriveKeyPair(ikmR);
  //     const derivedPkRm = await suite.kem.serializePublicKey(
  //       derivedR.publicKey,
  //     );
  //     assertEquals(new Uint8Array(derivedPkRm), pkRm);
  //     const derivedE = await suite.kem.deriveKeyPair(ikmE);
  //     const derivedPkEm = await suite.kem.serializePublicKey(
  //       derivedE.publicKey,
  //     );
  //     assertEquals(new Uint8Array(derivedPkEm), pkEm);
  //   });
  // });

  describe("with official test-vector for DhkemP256HkdfSha256.", () => {
    it("should derive a proper key pair.", async () => {
      if (isDenoV1()) {
        return;
      }
      const ikmR = hexToBytes(
        "d42ef874c1913d9568c9405407c805baddaffd0898a00f1e84e154fa787b2429",
      ).buffer as ArrayBuffer;
      const ikmE = hexToBytes(
        "2afa611d8b1a7b321c761b483b6a053579afa4f767450d3ad0f84a39fda587a6",
      ).buffer as ArrayBuffer;
      const pkRm = hexToBytes(
        "040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1",
      ).buffer as ArrayBuffer;
      const pkEm = hexToBytes(
        "04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f",
      ).buffer as ArrayBuffer;

      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });
      const derivedR = await suite.kem.deriveKeyPair(ikmR);
      const derivedPkRm = await suite.kem.serializePublicKey(
        derivedR.publicKey,
      );
      assertEquals(derivedPkRm, pkRm);
      const derivedE = await suite.kem.deriveKeyPair(ikmE);
      const derivedPkEm = await suite.kem.serializePublicKey(
        derivedE.publicKey,
      );
      assertEquals(derivedPkEm, pkEm);
    });
  });

  describe("with too long ikm", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      await assertRejects(
        () => suite.kem.deriveKeyPair((new Uint8Array(8193)).buffer),
        InvalidParamError,
        "Too long ikm",
      );
    });
  });
});

describe("importKey", () => {
  describe("with invalid EC(P-256) public key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const kStr = "aabbccddeeff";
      const k = hexToBytes(kStr).buffer as ArrayBuffer;

      // assert
      await assertRejects(
        () => suite.kem.importKey("raw", k),
        DeserializeError,
      );
    });
  });

  describe("with invalid EC(P-256) private key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const kStr = "aabbccddeeff";
      const k = hexToBytes(kStr).buffer as ArrayBuffer;

      // assert
      await assertRejects(
        () => suite.kem.importKey("raw", k, false),
        DeserializeError,
      );
    });
  });

  // describe("with invalid x25519 public key", () => {
  //   it("should throw DeserializeError", async () => {
  //     // setup
  //     const suite = new CipherSuite({
  //       kem: new DhkemX25519HkdfSha256(),
  //       kdf: new HkdfSha256(),
  //       aead: new Aes128Gcm(),
  //     });

  //     const kStr = "aabbccddeeff";
  //     const k = hexToBytes(kStr);

  //     // assert
  //     await assertRejects(
  //       () => suite.kem.importKey("raw", k),
  //       DeserializeError,
  //     );
  //   });
  // });

  // describe("with invalid x25519 private key", () => {
  //   it("should throw DeserializeError", async () => {
  //     // setup
  //     const suite = new CipherSuite({
  //       kem: new DhkemX25519HkdfSha256(),
  //       kdf: new HkdfSha256(),
  //       aead: new Aes128Gcm(),
  //     });

  //     const kStr = "aabbccddeeff";
  //     const k = hexToBytes(kStr);

  //     // assert
  //     await assertRejects(
  //       () => suite.kem.importKey("raw", k, false),
  //       DeserializeError,
  //     );
  //   });
  // });

  // describe("with invalid x448 public key", () => {
  //   it("should throw DeserializeError", async () => {
  //     // setup
  //     const suite = new CipherSuite({
  //       kem: new DhkemX448HkdfSha512(),
  //       kdf: new HkdfSha256(),
  //       aead: new Aes128Gcm(),
  //     });

  //     const kStr = "aabbccddeeff";
  //     const k = hexToBytes(kStr);

  //     // assert
  //     await assertRejects(
  //       () => suite.kem.importKey("raw", k),
  //       DeserializeError,
  //     );
  //   });
  // });

  // describe("with invalid x448 private key", () => {
  //   it("should throw DeserializeError", async () => {
  //     // setup
  //     const suite = new CipherSuite({
  //       kem: new DhkemX448HkdfSha512(),
  //       kdf: new HkdfSha256(),
  //       aead: new Aes128Gcm(),
  //     });

  //     const kStr = "aabbccddeeff";
  //     const k = hexToBytes(kStr);

  //     // assert
  //     await assertRejects(
  //       () => suite.kem.importKey("raw", k, false),
  //       DeserializeError,
  //     );
  //   });
  // });
});
