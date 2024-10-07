import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";

import { isNode } from "@hpke/common";

import type { ConformanceTester } from "./conformanceTester.ts";
import type { WycheproofTestVector } from "./testVector.ts";

import { createConformanceTester } from "./conformanceTester.ts";
import { getPath } from "./utils.ts";

describe("EC key validation", () => {
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

  describe("P-256", () => {
    it("should validate properly", async () => {
      if (!isNode()) {
        return;
      }

      // Use test vectors quoted from https://github.com/google/wycheproof under Apache-2.0 license.
      const tv: WycheproofTestVector = JSON.parse(
        await Deno.readTextFile(
          getPath("../../../test/vectors/ecdh_secp256r1_ecpoint_test.json"),
        ),
      );

      totalCount += tv.testGroups[0].tests.length;

      for (const v of tv.testGroups[0].tests) {
        if (v.result === "invalid") {
          await tester.testInvalidEcPublicKey("P-256", v.public);
        } else {
          await tester.testValidEcPublicKey("P-256", v.public);
        }
      }
    });
  });

  describe("P-384", () => {
    it("should validate properly", async () => {
      if (!isNode()) {
        return;
      }

      // Use test vectors quoted from https://github.com/google/wycheproof under Apache-2.0 license.
      const tv: WycheproofTestVector = JSON.parse(
        await Deno.readTextFile(
          getPath("../../../test/vectors/ecdh_secp384r1_ecpoint_test.json"),
        ),
      );

      totalCount += tv.testGroups[0].tests.length;

      for (const v of tv.testGroups[0].tests) {
        if (v.result === "invalid") {
          await tester.testInvalidEcPublicKey("P-384", v.public);
        } else {
          await tester.testValidEcPublicKey("P-384", v.public);
        }
      }
    });
  });

  describe("P-521", () => {
    it("should validate properly", async () => {
      if (!isNode()) {
        return;
      }

      // Use test vectors quoted from https://github.com/google/wycheproof under Apache-2.0 license.
      const tv: WycheproofTestVector = JSON.parse(
        await Deno.readTextFile(
          getPath("../../../test/vectors/ecdh_secp521r1_ecpoint_test.json"),
        ),
      );

      totalCount += tv.testGroups[0].tests.length;

      for (const v of tv.testGroups[0].tests) {
        if (v.result === "invalid") {
          await tester.testInvalidEcPublicKey("P-521", v.public);
        } else {
          await tester.testValidEcPublicKey("P-521", v.public);
        }
      }
    });
  });
});
