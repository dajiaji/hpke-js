import crypto from 'crypto';
import fs from 'fs';

import type { TestVector } from './testVector';
import { testConformance } from './testVector';

describe('RFC9180 conformance', () => {
  // test vectors
  let testVectors: TestVector[];
  let testCount: number;

  beforeAll(async () => {

    Object.defineProperty(global.self, 'crypto', { value: crypto.webcrypto });

    testVectors = JSON.parse(fs.readFileSync('./test/vectors/test-vectors.json', 'utf8'));
    testCount = 0;
  });

  afterAll(() => {
    console.log(`passed/total: ${testCount}/${testVectors.length}`);
    
  });

  describe('Base/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          await testConformance(v);
          testCount++;
        }
      }
    });
  });

  describe('Base/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id < 0x0020 && v.aead_id == 0xFFFF) {
          await testConformance(v);
          testCount++;
        }
      }
    });
  });

  describe('PSK/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          await testConformance(v);
          testCount++;
        }
      }
    });
  });

  describe('PSK/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id < 0x0020 && v.aead_id == 0xFFFF) {
          await testConformance(v);
          testCount++;
        }
      }
    });
  });

  describe('Auth/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          await testConformance(v);
          testCount++;
        }
      }
    });
  });

  describe('Auth/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id < 0x0020 && v.aead_id == 0xFFFF) {
          await testConformance(v);
          testCount++;
        }
      }
    });
  });

  describe('AuthPSK/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          await testConformance(v);
          testCount++;
        }
      }
    });
  });

  describe('AuthPSK/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json', () => {
    it('should match demonstrated values', async () => {

      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id < 0x0020 && v.aead_id == 0xFFFF) {
          await testConformance(v);
          testCount++;
        }
      }
    });
  });

});
