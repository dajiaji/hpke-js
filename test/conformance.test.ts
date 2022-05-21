import fs from 'fs';

import type { ConformanceTester } from './conformanceTester';
import type { TestVector } from './testVector';

import { createConformanceTester } from './conformanceTester';

describe('RFC9180 conformance', () => {
  let testVectors: TestVector[];
  let tester: ConformanceTester;

  beforeAll(async () => {
    testVectors = JSON.parse(fs.readFileSync('./test/vectors/test-vectors.json', 'utf8'));
    tester = await createConformanceTester();
  });

  afterAll(() => {
    const count = tester.count();
    console.log(`passed/total: ${count}/${testVectors.length}`);

  });

  describe('Base/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          await tester.test(v);
        }
      }
    });
  });

  describe('Base/DhkemP*/HkdfSha*/ChaCha20Poly1305 in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id < 0x0020 && v.aead_id == 0x0003) {
          await tester.test(v);
        }
      }
    });
  });

  describe('Base/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id < 0x0020 && v.aead_id == 0xFFFF) {
          await tester.test(v);
        }
      }
    });
  });

  describe('PSK/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          await tester.test(v);
        }
      }
    });
  });

  describe('PSK/DhkemP*/HkdfSha*/ChaCha20Poly1305 in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id < 0x0020 && v.aead_id == 0x0003) {
          await tester.test(v);
        }
      }
    });
  });

  describe('PSK/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id < 0x0020 && v.aead_id == 0xFFFF) {
          await tester.test(v);
        }
      }
    });
  });

  describe('Auth/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          await tester.test(v);
        }
      }
    });
  });

  describe('Auth/DhkemP*/HkdfSha*/ChaCha20Poly1305 in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id < 0x0020 && v.aead_id == 0x0003) {
          await tester.test(v);
        }
      }
    });
  });

  describe('Auth/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id < 0x0020 && v.aead_id == 0xFFFF) {
          await tester.test(v);
        }
      }
    });
  });

  describe('AuthPSK/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          await tester.test(v);
        }
      }
    });
  });

  describe('AuthPSK/DhkemP*/HkdfSha*/ChaCha20Poly1305 in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id < 0x0020 && v.aead_id == 0x0003) {
          await tester.test(v);
        }
      }
    });
  });

  describe('AuthPSK/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id < 0x0020 && v.aead_id == 0xFFFF) {
          await tester.test(v);
        }
      }
    });
  });

});
