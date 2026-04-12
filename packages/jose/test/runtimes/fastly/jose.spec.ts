import { describe, expect, it } from "vitest";

const origin = process.env.FASTLY_TEST_ORIGIN ?? "http://127.0.0.1:7676";

describe("Fastly Compute", () => {
  describe("Integrated Encryption with HPKE-0 (P-256, AES-128-GCM)", () => {
    it("should return ng", async () => {
      const res = await fetch(
        `${origin}/test?case=integrated-hpke0`,
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toMatch(/^ng:/);
    });
  });

  describe("Integrated Encryption with HPKE-3 (X25519, AES-128-GCM)", () => {
    it("should return ng", async () => {
      const res = await fetch(
        `${origin}/test?case=integrated-hpke3`,
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toMatch(/^ng:/);
    });
  });

  describe("Key Encryption with HPKE-0-KE (P-256, A128GCM content)", () => {
    it("should return ng", async () => {
      const res = await fetch(
        `${origin}/test?case=ke-hpke0`,
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toMatch(/^ng:/);
    });
  });

  describe("Key Encryption with HPKE-3-KE (X25519, A128GCM content)", () => {
    it("should return ng", async () => {
      const res = await fetch(
        `${origin}/test?case=ke-hpke3`,
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toMatch(/^ng:/);
    });
  });
});
