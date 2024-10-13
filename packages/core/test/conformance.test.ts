import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";

import { isDeno, isDenoV1 } from "@hpke/common";

import type { ConformanceTester } from "./conformanceTester.ts";
import type { TestVector } from "./testVector.ts";

import { createConformanceTester } from "./conformanceTester.ts";
import { getPath } from "./utils.ts";

describe("RFC9180 conformance", () => {
  let testVectors: TestVector[];
  let tester: ConformanceTester;

  beforeAll(async () => {
    testVectors = JSON.parse(
      await Deno.readTextFile(
        getPath("../../../test/vectors/test-vectors.json"),
      ),
    );
    tester = await createConformanceTester();
  });

  afterAll(() => {
    const count = tester.count();
    console.log(`passed/total: ${count}/${testVectors.length}`);
  });

  describe("Base/DhkemP256/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id === 0x0010 && v.aead_id <= 0x0002) {
          if (isDenoV1()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("Base/DhkemP384/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id === 0x0011 && v.aead_id <= 0x0002) {
          await tester.test(v);
        }
      }
    });
  });

  describe("Base/DhkemP521/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id === 0x0012 && v.aead_id <= 0x0002) {
          if (isDeno()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("Base/DhkemP*/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 0 && v.kem_id < 0x0020 && v.aead_id === 0x0003) {
  //         if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
  //           continue;
  //         }
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("Base/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id < 0x0020 && v.aead_id === 0xFFFF) {
          if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("Base/DhkemX25519/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id === 0x0020 && v.aead_id <= 0x0002) {
          if (isDenoV1()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("Base/DhkemX25519/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 0 && v.kem_id === 0x0020 && v.aead_id === 0x0003) {
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("Base/DhkemX25519/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id === 0x0020 && v.aead_id === 0xFFFF) {
          if (isDenoV1()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("Base/DhkemX448/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id === 0x0021 && v.aead_id <= 0x0002) {
          if (isDeno()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("Base/DhkemX448/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 0 && v.kem_id === 0x0021 && v.aead_id === 0x0003) {
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("Base/DhkemX448/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 0 && v.kem_id === 0x0021 && v.aead_id === 0xFFFF) {
          if (isDeno()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("PSK/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("PSK/DhkemP*/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 1 && v.kem_id < 0x0020 && v.aead_id === 0x0003) {
  //         if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
  //           continue;
  //         }
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("PSK/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id < 0x0020 && v.aead_id === 0xFFFF) {
          if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("PSK/DhkemX25519/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id === 0x0020 && v.aead_id <= 0x0002) {
          if (isDenoV1()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("PSK/DhkemX25519/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 1 && v.kem_id === 0x0020 && v.aead_id === 0x0003) {
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("PSK/DhkemX25519/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id === 0x0020 && v.aead_id === 0xFFFF) {
          if (isDenoV1()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("PSK/DhkemX448/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id === 0x0021 && v.aead_id <= 0x0002) {
          if (isDeno()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("PSK/DhkemX448/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 1 && v.kem_id === 0x0021 && v.aead_id === 0x0003) {
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("PSK/DhkemX448/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 1 && v.kem_id === 0x0021 && v.aead_id === 0xFFFF) {
          if (isDeno()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("Auth/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("Auth/DhkemP*/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 2 && v.kem_id < 0x0020 && v.aead_id === 0x0003) {
  //         if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
  //           continue;
  //         }
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("Auth/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id < 0x0020 && v.aead_id === 0xFFFF) {
          if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("Auth/DhkemX25519/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id === 0x0020 && v.aead_id <= 0x0002) {
          if (isDenoV1()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("Auth/DhkemX25519/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 2 && v.kem_id === 0x0020 && v.aead_id === 0x0003) {
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("Auth/DhkemX25519/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id === 0x0020 && v.aead_id === 0xFFFF) {
          if (isDenoV1()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("Auth/DhkemX448/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id === 0x0021 && v.aead_id <= 0x0002) {
          if (isDeno()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("Auth/DhkemX448/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 2 && v.kem_id === 0x0021 && v.aead_id === 0x0003) {
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("Auth/DhkemX448/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 2 && v.kem_id === 0x0021 && v.aead_id === 0xFFFF) {
          if (isDeno()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("AuthPSK/DhkemP*/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id < 0x0020 && v.aead_id <= 0x0002) {
          if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("AuthPSK/DhkemP*/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 3 && v.kem_id < 0x0020 && v.aead_id === 0x0003) {
  //         if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
  //           continue;
  //         }
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("AuthPSK/DhkemP*/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id < 0x0020 && v.aead_id === 0xFFFF) {
          if (isDenoV1() || (v.kem_id === 0x0012 && isDeno())) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("AuthPSK/DhkemX25519/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id === 0x0020 && v.aead_id <= 0x0002) {
          if (isDenoV1()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("AuthPSK/DhkemX25519/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 3 && v.kem_id === 0x0020 && v.aead_id === 0x0003) {
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("AuthPSK/DhkemX25519/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id === 0x0020 && v.aead_id === 0xFFFF) {
          if (isDenoV1()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  describe("AuthPSK/DhkemX448/HkdfSha*/Aes*Gcm in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id === 0x0021 && v.aead_id <= 0x0002) {
          if (isDeno()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });

  // describe("AuthPSK/DhkemX448/HkdfSha*/ChaCha20Poly1305 in test-vectors.json", () => {
  //   it("should match demonstrated values", async () => {
  //     for (const v of testVectors) {
  //       if (v.mode === 3 && v.kem_id === 0x0021 && v.aead_id === 0x0003) {
  //         await tester.test(v);
  //       }
  //     }
  //   });
  // });

  describe("AuthPSK/DhkemX448/HkdfSha*/ExportOnly in test-vectors.json", () => {
    it("should match demonstrated values", async () => {
      for (const v of testVectors) {
        if (v.mode === 3 && v.kem_id === 0x0021 && v.aead_id === 0xFFFF) {
          if (isDeno()) {
            continue;
          }
          await tester.test(v);
        }
      }
    });
  });
});
