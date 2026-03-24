import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { deserializeKeyConfig, serializeKeyConfig } from "../mod.ts";
import type { OhttpKeyConfig } from "../mod.ts";

describe("KeyConfig", () => {
  describe("serialize / deserialize roundtrip", () => {
    it("should roundtrip a single config with X25519", () => {
      const config: OhttpKeyConfig = {
        keyId: 0x01,
        kem: 0x0020, // DHKEM(X25519, HKDF-SHA256)
        publicKey: new Uint8Array(32).fill(0xab),
        cipherSuites: [
          { kdf: 0x0001, aead: 0x0001 }, // HKDF-SHA256, AES-128-GCM
        ],
      };

      const serialized = serializeKeyConfig(config);
      const deserialized = deserializeKeyConfig(serialized);

      assertEquals(deserialized.length, 1);
      assertEquals(deserialized[0].keyId, config.keyId);
      assertEquals(deserialized[0].kem, config.kem);
      assertEquals(deserialized[0].publicKey, config.publicKey);
      assertEquals(deserialized[0].cipherSuites, config.cipherSuites);
    });

    it("should roundtrip a config with multiple cipher suites", () => {
      const config: OhttpKeyConfig = {
        keyId: 0xff,
        kem: 0x0020,
        publicKey: new Uint8Array(32).fill(0xcd),
        cipherSuites: [
          { kdf: 0x0001, aead: 0x0001 },
          { kdf: 0x0001, aead: 0x0002 },
        ],
      };

      const serialized = serializeKeyConfig(config);
      const deserialized = deserializeKeyConfig(serialized);

      assertEquals(deserialized.length, 1);
      assertEquals(deserialized[0].cipherSuites.length, 2);
      assertEquals(deserialized[0].cipherSuites[1].aead, 0x0002);
    });

    it("should roundtrip a P-256 config", () => {
      const config: OhttpKeyConfig = {
        keyId: 0x02,
        kem: 0x0010, // DHKEM(P-256, HKDF-SHA256)
        publicKey: new Uint8Array(65).fill(0x04),
        cipherSuites: [
          { kdf: 0x0001, aead: 0x0001 },
        ],
      };

      const serialized = serializeKeyConfig(config);
      const deserialized = deserializeKeyConfig(serialized);

      assertEquals(deserialized.length, 1);
      assertEquals(deserialized[0].kem, 0x0010);
      assertEquals(deserialized[0].publicKey.length, 65);
    });

    it("should deserialize concatenated configs", () => {
      const config1: OhttpKeyConfig = {
        keyId: 0x01,
        kem: 0x0020,
        publicKey: new Uint8Array(32).fill(0xaa),
        cipherSuites: [{ kdf: 0x0001, aead: 0x0001 }],
      };
      const config2: OhttpKeyConfig = {
        keyId: 0x02,
        kem: 0x0020,
        publicKey: new Uint8Array(32).fill(0xbb),
        cipherSuites: [{ kdf: 0x0001, aead: 0x0002 }],
      };

      const s1 = serializeKeyConfig(config1);
      const s2 = serializeKeyConfig(config2);
      const combined = new Uint8Array(s1.length + s2.length);
      combined.set(s1, 0);
      combined.set(s2, s1.length);

      const deserialized = deserializeKeyConfig(combined);
      assertEquals(deserialized.length, 2);
      assertEquals(deserialized[0].keyId, 0x01);
      assertEquals(deserialized[1].keyId, 0x02);
    });
  });

  describe("deserialize errors", () => {
    it("should throw on truncated data", () => {
      assertThrows(
        () => deserializeKeyConfig(new Uint8Array([0x00])),
        Error,
        "Truncated",
      );
    });

    it("should throw on invalid cipher suite length", () => {
      // Build a config where csLen is not a multiple of 4
      const buf = new Uint8Array(2 + 1 + 2 + 32 + 2);
      const view = new DataView(buf.buffer);
      view.setUint16(0, 1 + 2 + 32 + 2); // configLen
      buf[2] = 0x01; // keyId
      view.setUint16(3, 0x0020); // kem
      // publicKey: 32 zero bytes
      view.setUint16(2 + 1 + 2 + 32, 3); // csLen = 3 (not multiple of 4)
      assertThrows(
        () => deserializeKeyConfig(buf),
        Error,
        "multiple of 4",
      );
    });
  });
});
