import type { AeadId, KdfId, KemId } from "../src/identifiers.ts";

interface TestVectorEncryption {
  aad: string;
  ct: string;
  nonce: string;
  pt: string;
}

interface TestVectorExport {
  exporter_context: string;
  L: number;
  exported_value: string;
}

export interface TestVector {
  mode: number;
  kem_id: KemId;
  kdf_id: KdfId;
  aead_id: AeadId;
  psk_id?: string;
  psk?: string;
  info: string;
  ikmR: string;
  ikmE: string;
  skRm: string;
  skSm?: string;
  skEm: string;
  pkRm: string;
  pkSm?: string;
  pkEm: string;
  ier: string;
  enc: string;
  shared_secret: string;
  key_schedule_context: string;
  secret: string;
  key: string;
  base_nonce: string;
  exporter_secret: string;
  encryptions: Array<TestVectorEncryption>;
  exports: Array<TestVectorExport>;
}

// The minimum interface to load test vectors on https://github.com/google/wycheproof
interface WycheproofTestCase {
  tcId: number;
  public: string;
  flags: Array<string>;
  result: string;
}

// The minimum interface to load test vectors on https://github.com/google/wycheproof
interface WycheproofTestGroup {
  tests: Array<WycheproofTestCase>;
}

// The minimum interface to load test vectors on https://github.com/google/wycheproof
export interface WycheproofTestVector {
  numberOfTests: number;
  testGroups: Array<WycheproofTestGroup>;
}
