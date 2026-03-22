import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { chacha20poly1305 } from "../src/chacha/chacha.ts";

function hexToBytes(hex: string): Uint8Array {
  const res = hex.match(/[\da-f]{2}/gi);
  if (!res) return new Uint8Array(0);
  return new Uint8Array(res.map((h) => parseInt(h, 16)));
}

function bytesToHex(v: Uint8Array): string {
  return [...v].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Wycheproof JSON types
// ---------------------------------------------------------------------------

interface WycheproofTestCase {
  tcId: number;
  comment: string;
  flags: string[];
  key: string;
  iv: string;
  aad: string;
  msg: string;
  ct: string;
  tag: string;
  result: "valid" | "invalid";
}

interface WycheproofTestGroup {
  ivSize: number;
  keySize: number;
  tagSize: number;
  type: string;
  tests: WycheproofTestCase[];
}

interface WycheproofTestFile {
  numberOfTests: number;
  testGroups: WycheproofTestGroup[];
}

// ==========================================================================
// RFC 7539 Section 2.8.2 - AEAD test vector
//
// Source: https://www.rfc-editor.org/rfc/rfc7539#section-2.8.2
// ==========================================================================

const RFC7539_VECTOR = {
  key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  iv: "070000004041424344454647",
  aad: "50515253c0c1c2c3c4c5c6c7",
  msg:
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
  ct:
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
  tag: "1ae10b594f09e26a7e902ecbd0600691",
};

// ==========================================================================
// Tests
// ==========================================================================

describe("chacha20poly1305 - RFC 7539 test vector", () => {
  it("should encrypt correctly", () => {
    const key = hexToBytes(RFC7539_VECTOR.key);
    const iv = hexToBytes(RFC7539_VECTOR.iv);
    const aad = hexToBytes(RFC7539_VECTOR.aad);
    const msg = hexToBytes(RFC7539_VECTOR.msg);

    const sealed = chacha20poly1305(key, iv, aad).encrypt(msg);
    const ct = sealed.subarray(0, sealed.length - 16);
    const tag = sealed.subarray(sealed.length - 16);

    assertEquals(bytesToHex(ct), RFC7539_VECTOR.ct);
    assertEquals(bytesToHex(tag), RFC7539_VECTOR.tag);
  });

  it("should decrypt correctly", () => {
    const key = hexToBytes(RFC7539_VECTOR.key);
    const iv = hexToBytes(RFC7539_VECTOR.iv);
    const aad = hexToBytes(RFC7539_VECTOR.aad);
    const ctAndTag = hexToBytes(RFC7539_VECTOR.ct + RFC7539_VECTOR.tag);

    const pt = chacha20poly1305(key, iv, aad).decrypt(ctAndTag);
    assertEquals(bytesToHex(pt), RFC7539_VECTOR.msg);
  });
});

describe("chacha20poly1305 - Wycheproof (chacha20_poly1305_test.json)", () => {
  const data: WycheproofTestFile = JSON.parse(
    Deno.readTextFileSync(
      new URL("./vectors/chacha20_poly1305_test.json", import.meta.url),
    ),
  );

  // Only test groups with standard 96-bit (12-byte) IV
  const standardGroups = data.testGroups.filter((g) => g.ivSize === 96);

  const validCases = standardGroups.flatMap((g) =>
    g.tests.filter((t) => t.result === "valid")
  );
  const invalidCases = standardGroups.flatMap((g) =>
    g.tests.filter((t) => t.result === "invalid")
  );

  describe("valid vectors (encryption)", () => {
    it(`should pass all ${validCases.length} valid vectors`, () => {
      let passed = 0;
      const errors: string[] = [];

      for (const tc of validCases) {
        try {
          const key = hexToBytes(tc.key);
          const iv = hexToBytes(tc.iv);
          const aad = hexToBytes(tc.aad);
          const msg = hexToBytes(tc.msg);

          const sealed = chacha20poly1305(key, iv, aad).encrypt(msg);
          const ct = sealed.subarray(0, sealed.length - 16);
          const tag = sealed.subarray(sealed.length - 16);

          const expectedCt = tc.ct;
          const expectedTag = tc.tag;

          if (
            bytesToHex(ct) !== expectedCt || bytesToHex(tag) !== expectedTag
          ) {
            errors.push(
              `tcId ${tc.tcId}: ciphertext or tag mismatch`,
            );
          } else {
            passed++;
          }
        } catch (e: unknown) {
          errors.push(`tcId ${tc.tcId}: threw ${(e as Error).message}`);
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

  describe("valid vectors (decryption)", () => {
    it(`should pass all ${validCases.length} valid vectors`, () => {
      let passed = 0;
      const errors: string[] = [];

      for (const tc of validCases) {
        try {
          const key = hexToBytes(tc.key);
          const iv = hexToBytes(tc.iv);
          const aad = hexToBytes(tc.aad);
          const ctAndTag = hexToBytes(tc.ct + tc.tag);

          const pt = chacha20poly1305(key, iv, aad).decrypt(ctAndTag);

          if (bytesToHex(pt) !== tc.msg) {
            errors.push(`tcId ${tc.tcId}: plaintext mismatch`);
          } else {
            passed++;
          }
        } catch (e: unknown) {
          errors.push(`tcId ${tc.tcId}: threw ${(e as Error).message}`);
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

  describe("invalid vectors (decryption must reject)", () => {
    it(`should reject all ${invalidCases.length} invalid vectors`, () => {
      let rejected = 0;
      const falseAccepts: string[] = [];

      for (const tc of invalidCases) {
        try {
          const key = hexToBytes(tc.key);
          const iv = hexToBytes(tc.iv);
          const aad = hexToBytes(tc.aad);
          const ctAndTag = hexToBytes(tc.ct + tc.tag);

          chacha20poly1305(key, iv, aad).decrypt(ctAndTag);
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
        `False accepts:\n${falseAccepts.join("\n")}`,
      );
      console.log(
        `    invalid: ${rejected}/${invalidCases.length} rejected`,
      );
    });
  });

  // Non-standard IV sizes should be rejected
  describe("non-standard IV sizes (must reject)", () => {
    const nonStandardGroups = data.testGroups.filter((g) => g.ivSize !== 96);
    const nonStdCases = nonStandardGroups.flatMap((g) => g.tests);

    it(`should reject all ${nonStdCases.length} non-standard IV vectors`, () => {
      let rejected = 0;
      const falseAccepts: string[] = [];

      for (const tc of nonStdCases) {
        try {
          const key = hexToBytes(tc.key);
          const iv = hexToBytes(tc.iv);
          const aad = hexToBytes(tc.aad);
          const msg = hexToBytes(tc.msg);

          chacha20poly1305(key, iv, aad).encrypt(msg);
          falseAccepts.push(
            `tcId ${tc.tcId} (ivSize=${iv.length}): should have been rejected`,
          );
        } catch {
          rejected++;
        }
      }

      assertEquals(
        falseAccepts.length,
        0,
        `False accepts on non-standard IV:\n${falseAccepts.join("\n")}`,
      );
      assertEquals(rejected, nonStdCases.length);
    });
  });
});
