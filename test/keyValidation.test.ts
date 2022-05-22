import fs from 'fs';

import type { ConformanceTester } from './conformanceTester';
import type { WycheproofTestVector } from './testVector';

import { createConformanceTester } from './conformanceTester';

describe('EC public key validation', () => {

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

  describe('P-256', () => {
    it('should validate properly', async () => {
      // Use test vectors quoted from https://github.com/google/wycheproof under Apache-2.0 license.
      const tv: WycheproofTestVector = JSON.parse(
        fs.readFileSync('./test/vectors/ecdh_secp256r1_ecpoint_test.json', 'utf8'),
      );

      totalCount += tv.testGroups[0].tests.length;

      for (const v of tv.testGroups[0].tests) {
        if (v.result === 'invalid') {
          await tester.testInvalidEcPublicKey('P-256', v.public);
        } else {
          await tester.testValidEcPublicKey('P-256', v.public);
        }
      }
    });
  });

  describe('P-384', () => {
    it('should validate properly', async () => {
      // Use test vectors quoted from https://github.com/google/wycheproof under Apache-2.0 license.
      const tv: WycheproofTestVector = JSON.parse(
        fs.readFileSync('./test/vectors/ecdh_secp384r1_ecpoint_test.json', 'utf8'),
      );

      totalCount += tv.testGroups[0].tests.length;

      for (const v of tv.testGroups[0].tests) {
        if (v.result === 'invalid') {
          await tester.testInvalidEcPublicKey('P-384', v.public);
        } else {
          await tester.testValidEcPublicKey('P-384', v.public);
        }
      }
    });
  });

  describe('P-521', () => {
    it('should validate properly', async () => {
      // Use test vectors quoted from https://github.com/google/wycheproof under Apache-2.0 license.
      const tv: WycheproofTestVector = JSON.parse(
        fs.readFileSync('./test/vectors/ecdh_secp521r1_ecpoint_test.json', 'utf8'),
      );

      totalCount += tv.testGroups[0].tests.length;

      for (const v of tv.testGroups[0].tests) {
        if (v.result === 'invalid') {
          await tester.testInvalidEcPublicKey('P-521', v.public);
        } else {
          await tester.testValidEcPublicKey('P-521', v.public);
        }
      }
    });
  });
});
