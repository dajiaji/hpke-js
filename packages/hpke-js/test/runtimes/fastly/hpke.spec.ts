import { describe, expect, it } from "vitest";

const origin = process.env.FASTLY_TEST_ORIGIN ?? "http://127.0.0.1:7676";

async function expectUnsupportedRuntime(
  kem: string,
  kdf: string,
  aead: string,
) {
  const res = await fetch(
    `${origin}/test?kem=${kem}&kdf=${kdf}&aead=${aead}`,
  );
  expect(res.status).toBe(200);
  expect(await res.text()).toMatch(/^ng:/);
}

describe("Fastly Compute", () => {
  describe("GET /test?kem=0x0010", () => {
    it("should return ng", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002", "0x0003"]) {
          await expectUnsupportedRuntime("0x0010", kdf, aead);
        }
      }
    });
  });

  describe("GET /test?kem=0x0011", () => {
    it("should return ng", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002", "0x0003"]) {
          await expectUnsupportedRuntime("0x0011", kdf, aead);
        }
      }
    });
  });

  describe("GET /test?kem=0x0012", () => {
    it("should return ng", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002", "0x0003"]) {
          await expectUnsupportedRuntime("0x0012", kdf, aead);
        }
      }
    });
  });

  // X25519/X448 KEM itself is pure JS (@noble/curves), but the HKDF key
  // schedule uses crypto.subtle.importKey("HKDF") + deriveBits which Fastly
  // does not support yet.  Therefore all suites fail on Fastly for now.
  describe("GET /test?kem=0x0020", () => {
    it("should return ng", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002", "0x0003"]) {
          await expectUnsupportedRuntime("0x0020", kdf, aead);
        }
      }
    });
  });

  describe("GET /test?kem=0x0021", () => {
    it("should return ng", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002", "0x0003"]) {
          await expectUnsupportedRuntime("0x0021", kdf, aead);
        }
      }
    });
  });
});
