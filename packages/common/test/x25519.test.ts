import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { hexToBytes, x25519 } from "../mod.ts";

describe("x25519", () => {
  it("should reject an all-zero public key", () => {
    const secretKey = new Uint8Array(32).fill(0xff);
    assertThrows(
      () => x25519.getSharedSecret(secretKey, new Uint8Array(32)),
      Error,
    );
  });

  it("should preserve the secret key when deriving a public key", () => {
    // Clamping changes both ends of this scalar unless it is copied first.
    const secretKey = new Uint8Array(32).fill(0xff);
    const original = secretKey.slice();
    x25519.getPublicKey(secretKey);
    assertEquals(secretKey, original);
  });

  it("should preserve the secret key when deriving a shared secret", () => {
    const secretKey = new Uint8Array(32).fill(0xff);
    const original = secretKey.slice();
    const publicKey = hexToBytes(
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    );
    x25519.getSharedSecret(secretKey, publicKey);
    assertEquals(secretKey, original);
  });

  // https://www.rfc-editor.org/rfc/rfc7748.html#section-5.2
  describe("RFC 7748 section 5.2", () => {
    const vectors = [
      {
        scalar:
          "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        u: "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        expected:
          "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
      },
      {
        scalar:
          "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        u: "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        expected:
          "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
      },
    ];

    for (const [index, vector] of vectors.entries()) {
      it(`should match scalar multiplication vector ${index + 1}`, () => {
        assertEquals(
          x25519.getSharedSecret(
            hexToBytes(vector.scalar),
            hexToBytes(vector.u),
          ),
          hexToBytes(vector.expected),
        );
      });
    }

    it("should match the one-iteration vector", () => {
      const initial = hexToBytes(
        "0900000000000000000000000000000000000000000000000000000000000000",
      );
      assertEquals(
        x25519.getSharedSecret(initial, initial),
        hexToBytes(
          "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        ),
      );
    });
  });

  // https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
  describe("RFC 7748 section 6.1", () => {
    const alicePrivate = hexToBytes(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    );
    const alicePublic = hexToBytes(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    );
    const bobPrivate = hexToBytes(
      "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    );
    const bobPublic = hexToBytes(
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    );
    const sharedSecret = hexToBytes(
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    );

    it("should derive Alice's and Bob's public keys", () => {
      assertEquals(x25519.getPublicKey(alicePrivate), alicePublic);
      assertEquals(x25519.getPublicKey(bobPrivate), bobPublic);
    });

    it("should derive the expected shared secret for both parties", () => {
      assertEquals(
        x25519.getSharedSecret(alicePrivate, bobPublic),
        sharedSecret,
      );
      assertEquals(
        x25519.getSharedSecret(bobPrivate, alicePublic),
        sharedSecret,
      );
    });
  });
});
