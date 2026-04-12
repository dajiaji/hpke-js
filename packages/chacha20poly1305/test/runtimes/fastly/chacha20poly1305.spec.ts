import { describe, expect, it } from "vitest";

const origin = process.env.FASTLY_TEST_ORIGIN ?? "http://127.0.0.1:7676";

async function expectUnsupportedRuntime(
  kem: string,
  kdf: string,
) {
  const res = await fetch(
    `${origin}/test?kem=${kem}&kdf=${kdf}`,
  );
  expect(res.status).toBe(200);
  expect(await res.text()).toMatch(/^ng:/);
}

describe("Fastly Compute", () => {
  describe("GET /test?kem=0x0010", () => {
    it("should return ng", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        await expectUnsupportedRuntime("0x0010", kdf);
      }
    });
  });

  describe("GET /test?kem=0x0011", () => {
    it("should return ng", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        await expectUnsupportedRuntime("0x0011", kdf);
      }
    });
  });

  describe("GET /test?kem=0x0012", () => {
    it("should return ng", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        await expectUnsupportedRuntime("0x0012", kdf);
      }
    });
  });
});
