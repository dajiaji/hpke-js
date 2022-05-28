import fs from 'fs';

import type { ConformanceTester } from './conformanceTester';
import type { WycheproofTestVector } from './testVector';

import { createConformanceTester } from './conformanceTester';

describe('X448 key validation', () => {

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

  describe('X448', () => {
    it('should validate properly', async () => {
      // Use test vectors quoted from https://github.com/google/wycheproof under Apache-2.0 license.
      const tv: WycheproofTestVector = JSON.parse(
        fs.readFileSync('./test/vectors/x448_test.json', 'utf8'),
      );

      totalCount += tv.testGroups[0].tests.length;

      for (const v of tv.testGroups[0].tests) {
        if (v.flags.find(k => k === 'ZeroSharedSecret')) {
          await tester.testInvalidX448PublicKey(v.public);
        } else if (v.flags.find(k => k === 'NonCanonicalPublic')) {
          continue;
        } else {
          await tester.testValidX448PublicKey(v.public);
        }
      }
    });
  });
});
