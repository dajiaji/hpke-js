import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { X448 } from "../src/dhkemX448.ts";
import { HkdfSha512 } from "../src/hkdfSha512.ts";

function hexToBytes(hex: string): Uint8Array {
  const res = hex.match(/[\da-f]{2}/gi);
  if (!res) throw new Error("Invalid hex");
  return new Uint8Array(res.map((h) => parseInt(h, 16)));
}

function bytesToHex(v: Uint8Array): string {
  return [...v].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function createX448(): X448 {
  return new X448(new HkdfSha512());
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
// RFC 7748 Section 6.2 - Diffie-Hellman test vectors
//
// Source: https://www.rfc-editor.org/rfc/rfc7748#section-6.2
// ==========================================================================

const RFC7748_VECTORS = [
  {
    comment: "RFC 7748 Section 6.2 - X448 test vector 1",
    sk: "9a8f4925d1519f5775cf46b04b5800d4" +
      "ee9ee8bae8bc5565d498c28d" +
      "d9c9baf574a94197448973910063" +
      "82a6f127ab1d9ac2d8c0a598726b",
    pk: "3eb7a829b0cd20f5bcfc0b599b6feccf" +
      "6da4627107bdb0d4f345b430" +
      "27d8b972fc3e34fb4232a13c" +
      "a706dcb57aec3dae07bdc1c67bf33609",
    shared: "07fff4181ac6cc95ec1c16a94a0f74d1" +
      "2da232ce40a77552281d282b" +
      "b60c0b56fd2464c335543936" +
      "521c24403085d59a449a5037514a879d",
  },
  {
    comment: "RFC 7748 Section 6.2 - X448 test vector 2",
    sk: "1c306a7ac2a0e2e0990b294470cba339" +
      "e6453772b075811d8fad0d1d" +
      "6927c120bb5ee8972b0d3e21" +
      "374c9c921b09d1b0366f10b65173992d",
    pk: "9b08f7cc31b7e3e67d22d5aea121074a" +
      "273bd2b83de09c63faa73d2c" +
      "22c5d9bbc836647241d953d4" +
      "0c5b12da88120d53177f80e532c41fa0",
    shared: "07fff4181ac6cc95ec1c16a94a0f74d1" +
      "2da232ce40a77552281d282b" +
      "b60c0b56fd2464c335543936" +
      "521c24403085d59a449a5037514a879d",
  },
];

// ==========================================================================
// Public key derivation test vectors
//
// Source: RFC 7748 Section 6.2
// ==========================================================================

const PUBLIC_KEY_VECTORS = [
  {
    comment: "RFC 7748 Section 6.2 - Alice's key pair",
    sk: "9a8f4925d1519f5775cf46b04b5800d4" +
      "ee9ee8bae8bc5565d498c28d" +
      "d9c9baf574a94197448973910063" +
      "82a6f127ab1d9ac2d8c0a598726b",
    pk: "9b08f7cc31b7e3e67d22d5aea121074a" +
      "273bd2b83de09c63faa73d2c" +
      "22c5d9bbc836647241d953d4" +
      "0c5b12da88120d53177f80e532c41fa0",
  },
  {
    comment: "RFC 7748 Section 6.2 - Bob's key pair",
    sk: "1c306a7ac2a0e2e0990b294470cba339" +
      "e6453772b075811d8fad0d1d" +
      "6927c120bb5ee8972b0d3e21" +
      "374c9c921b09d1b0366f10b65173992d",
    pk: "3eb7a829b0cd20f5bcfc0b599b6feccf" +
      "6da4627107bdb0d4f345b430" +
      "27d8b972fc3e34fb4232a13c" +
      "a706dcb57aec3dae07bdc1c67bf33609",
  },
];

// ==========================================================================
// Tests
// ==========================================================================

describe("x448 - public key derivation (RFC 7748)", () => {
  const x = createX448();

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

describe("x448 - RFC 7748 ECDH test vectors", () => {
  const x = createX448();

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

describe("x448 - Wycheproof XDH (x448_test.json, all 510 vectors)", () => {
  // Source: https://github.com/google/wycheproof/blob/master/testvectors_v1/x448_test.json
  const data: WycheproofTestFile = JSON.parse(
    Deno.readTextFileSync(
      new URL("./vectors/x448_test.json", import.meta.url),
    ),
  );

  const x = createX448();

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

  // ------- invalid vectors: must be rejected -------
  describe("invalid vectors", () => {
    const invalidCases = data.testGroups.flatMap((g) =>
      g.tests.filter((t) => t.result === "invalid")
    );

    it(`should reject all ${invalidCases.length} invalid vectors`, async () => {
      let rejected = 0;
      const falseAccepts: string[] = [];

      for (const tc of invalidCases) {
        try {
          await runXdh(tc);
          falseAccepts.push(
            `tcId ${tc.tcId} (${tc.comment}): should have been rejected`,
          );
        } catch {
          rejected++;
        }
      }

      assertEquals(
        falseAccepts.length,
        0,
        `False accepts on invalid vectors:\n${falseAccepts.join("\n")}`,
      );
      console.log(
        `    invalid: ${rejected}/${invalidCases.length} rejected`,
      );
    });
  });
});

describe("x448 - ECDH commutativity", () => {
  const x = createX448();

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

describe("x448 - edge cases", () => {
  const x = createX448();

  it("should reject public key with invalid length", async () => {
    let threw = false;
    try {
      await x.deserializePublicKey(new Uint8Array(32).buffer);
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
        new Uint8Array(32).buffer as ArrayBuffer,
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
    assertEquals(pkBytes.length, 56);

    const skBytes = new Uint8Array(
      await x.serializePrivateKey(kp.privateKey),
    );
    assertEquals(skBytes.length, 56);
  });
});
