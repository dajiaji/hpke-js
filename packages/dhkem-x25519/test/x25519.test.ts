import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { X25519 } from "../src/dhkemX25519.ts";
import { HkdfSha256 } from "../src/hkdfSha256.ts";

function hexToBytes(hex: string): Uint8Array {
  const res = hex.match(/[\da-f]{2}/gi);
  if (!res) throw new Error("Invalid hex");
  return new Uint8Array(res.map((h) => parseInt(h, 16)));
}

function bytesToHex(v: Uint8Array): string {
  return [...v].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function createX25519(): X25519 {
  return new X25519(new HkdfSha256());
}

// ---------------------------------------------------------------------------
// Wycheproof JSON types
// ---------------------------------------------------------------------------

interface WycheproofTestCase {
  tcId: number;
  comment: string;
  flags: string[];
  public: string;
  private: string;
  shared: string;
  result: "valid" | "acceptable" | "invalid";
}

interface WycheproofTestGroup {
  curve: string;
  type: string;
  tests: WycheproofTestCase[];
}

interface WycheproofTestFile {
  numberOfTests: number;
  testGroups: WycheproofTestGroup[];
}

// ==========================================================================
// RFC 7748 Section 6.1 - Diffie-Hellman test vectors
//
// Source: https://www.rfc-editor.org/rfc/rfc7748#section-6.1
// ==========================================================================

const RFC7748_VECTORS = [
  {
    comment: "RFC 7748 Section 6.1 - X25519 test vector 1",
    sk: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    pk: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    shared: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  },
  {
    comment: "RFC 7748 Section 6.1 - X25519 test vector 2",
    sk: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    pk: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    shared: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  },
];

// ==========================================================================
// Public key derivation test vectors
//
// Source: RFC 7748 Section 6.1
// ==========================================================================

const PUBLIC_KEY_VECTORS = [
  {
    comment: "RFC 7748 Section 6.1 - Alice's key pair",
    sk: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    pk: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  },
  {
    comment: "RFC 7748 Section 6.1 - Bob's key pair",
    sk: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    pk: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  },
];

// ==========================================================================
// Tests
// ==========================================================================

describe("x25519 - public key derivation (RFC 7748)", () => {
  const x = createX25519();

  for (const v of PUBLIC_KEY_VECTORS) {
    it(v.comment, async () => {
      const sk = await x.importKey(
        "raw",
        hexToBytes(v.sk).buffer as ArrayBuffer,
        false,
      );
      const pk = await x.derivePublicKey(sk);
      const pkBytes = new Uint8Array(await x.serializePublicKey(pk));
      assertEquals(bytesToHex(pkBytes), v.pk);
    });
  }
});

describe("x25519 - RFC 7748 ECDH test vectors", () => {
  const x = createX25519();

  for (const v of RFC7748_VECTORS) {
    it(v.comment, async () => {
      const sk = await x.importKey(
        "raw",
        hexToBytes(v.sk).buffer as ArrayBuffer,
        false,
      );
      const pk = await x.importKey(
        "raw",
        hexToBytes(v.pk).buffer as ArrayBuffer,
        true,
      );

      const dhResult = new Uint8Array(await x.dh(sk, pk));
      assertEquals(bytesToHex(dhResult), v.shared);
    });
  }
});

describe("x25519 - Wycheproof XDH (x25519_test.json, all 518 vectors)", () => {
  // Source: https://github.com/google/wycheproof/blob/master/testvectors_v1/x25519_test.json
  const data: WycheproofTestFile = JSON.parse(
    Deno.readTextFileSync(
      new URL("./vectors/x25519_test.json", import.meta.url),
    ),
  );

  const x = createX25519();

  async function runXdh(tc: WycheproofTestCase): Promise<string> {
    const skBytes = hexToBytes(tc.private);
    const pkBytes = hexToBytes(tc.public);

    const sk = await x.importKey(
      "raw",
      skBytes.buffer as ArrayBuffer,
      false,
    );
    const pk = await x.importKey(
      "raw",
      pkBytes.buffer as ArrayBuffer,
      true,
    );

    const dhResult = new Uint8Array(await x.dh(sk, pk));
    return bytesToHex(dhResult);
  }

  // ------- valid vectors: must all produce correct shared secret -------
  describe("valid vectors", () => {
    const validCases = data.testGroups.flatMap((g) =>
      g.tests.filter((t) => t.result === "valid")
    );

    it(`should pass all ${validCases.length} valid vectors`, async () => {
      let passed = 0;
      const errors: string[] = [];

      for (const tc of validCases) {
        try {
          const shared = await runXdh(tc);
          if (shared !== tc.shared) {
            errors.push(
              `tcId ${tc.tcId}: expected ${tc.shared}, got ${shared}`,
            );
          } else {
            passed++;
          }
        } catch (e: unknown) {
          errors.push(
            `tcId ${tc.tcId}: threw ${(e as Error).message}`,
          );
        }
      }

      assertEquals(
        errors.length,
        0,
        `Failed ${errors.length}/${validCases.length} valid vectors:\n${
          errors.join("\n")
        }`,
      );
      assertEquals(passed, validCases.length);
    });
  });

  // ------- acceptable vectors -------
  describe("acceptable vectors", () => {
    const acceptableCases = data.testGroups.flatMap((g) =>
      g.tests.filter((t) => t.result === "acceptable")
    );

    it(`should handle acceptable vectors (${acceptableCases.length} total)`, async () => {
      let passed = 0;
      let skipped = 0;
      const errors: string[] = [];

      for (const tc of acceptableCases) {
        try {
          const shared = await runXdh(tc);
          if (shared !== tc.shared) {
            // For acceptable vectors, wrong result is a failure
            errors.push(
              `tcId ${tc.tcId}: expected ${tc.shared}, got ${shared}`,
            );
          } else {
            passed++;
          }
        } catch {
          // Acceptable vectors may legitimately fail.
          // Per Wycheproof: both accept and reject are valid for "acceptable".
          skipped++;
        }
      }

      assertEquals(
        errors.length,
        0,
        `Wrong result for ${errors.length} acceptable vectors:\n${
          errors.join("\n")
        }`,
      );
      console.log(
        `    acceptable: ${passed} passed, ${skipped} skipped (both OK per Wycheproof)`,
      );
    });
  });
});

describe("x25519 - ECDH commutativity", () => {
  const x = createX25519();

  it("dh(skA, pkB) === dh(skB, pkA)", async () => {
    const kp1 = await x.generateKeyPair();
    const kp2 = await x.generateKeyPair();

    const dh1 = new Uint8Array(
      await x.dh(kp1.privateKey, kp2.publicKey),
    );
    const dh2 = new Uint8Array(
      await x.dh(kp2.privateKey, kp1.publicKey),
    );

    assertEquals(bytesToHex(dh1), bytesToHex(dh2));
  });
});

describe("x25519 - edge cases", () => {
  const x = createX25519();

  it("should reject public key with invalid length", async () => {
    let threw = false;
    try {
      await x.deserializePublicKey(new Uint8Array(31).buffer);
    } catch {
      threw = true;
    }
    assertEquals(threw, true);
  });

  it("should reject private key with invalid length", async () => {
    let threw = false;
    try {
      await x.importKey(
        "raw",
        new Uint8Array(31).buffer as ArrayBuffer,
        false,
      );
    } catch {
      threw = true;
    }
    assertEquals(threw, true);
  });

  it("should generate valid key pairs", async () => {
    const kp = await x.generateKeyPair();
    const pkBytes = new Uint8Array(
      await x.serializePublicKey(kp.publicKey),
    );
    assertEquals(pkBytes.length, 32);

    const skBytes = new Uint8Array(
      await x.serializePrivateKey(kp.privateKey),
    );
    assertEquals(skBytes.length, 32);
  });
});
