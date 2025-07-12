import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";

import type { ConformanceTester } from "./conformanceTester.ts";
import type { WycheproofTestVector } from "./testVector.ts";

import { isDeno } from "@hpke/common";
import { createConformanceTester } from "./conformanceTester.ts";
import { getPath } from "./utils.ts";

describe("X25519 key validation", () => {
  let totalCount: number;
  let tester: ConformanceTester;

  beforeAll(async () => {
    tester = await createConformanceTester();
    totalCount = 0;
  });

  afterAll(() => {
    const count = tester.count();
    console.log(`passed/total: ${count}/${totalCount}`);
  });

  describe("X25519", () => {
    it("should validate properly", async () => {
      // Use test vectors quoted from https://github.com/google/wycheproof under Apache-2.0 license.
      const tv: WycheproofTestVector = JSON.parse(
        await Deno.readTextFile(
          getPath("../../../test/vectors/x25519_test.json"),
        ),
      );

      totalCount += tv.testGroups[0].tests.length;

      if (isDeno()) {
        for (const v of tv.testGroups[0].tests) {
          if (v.flags.find((k) => k === "ZeroSharedSecret")) {
            await tester.testInvalidX25519PublicKey(v.public);
          } else {
            await tester.testValidX25519PublicKey(v.public);
          }
        }
      } else {
        for (const v of tv.testGroups[0].tests) {
          if ([85, 86, 87, 88, 97].includes(v.tcId)) {
            // Skip test vectors that are dependent on the Node.js's crypto module implementation.
            continue;
          }
          if (v.flags.find((k) => k === "ZeroSharedSecret")) {
            await tester.testInvalidX25519PublicKey(v.public);
          } else {
            await tester.testValidX25519PublicKey(v.public);
          }
        }
      }
    });
  });
});
