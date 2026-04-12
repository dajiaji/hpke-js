import { describe, expect, it } from "vitest";

const origin = process.env.FASTLY_TEST_ORIGIN ?? "http://127.0.0.1:7676";

describe("Fastly Compute", () => {
  describe("OHTTP with X25519/AES-128-GCM", () => {
    it("should return ng", async () => {
      const res = await fetch(
        `${origin}/test?case=x25519-aes128gcm`,
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toMatch(/^ng:/);
    });
  });

  describe("OHTTP with X25519/AES-256-GCM", () => {
    it("should return ng", async () => {
      const res = await fetch(
        `${origin}/test?case=x25519-aes256gcm`,
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toMatch(/^ng:/);
    });
  });

  describe("OHTTP with P-256/AES-128-GCM", () => {
    it("should return ng", async () => {
      const res = await fetch(
        `${origin}/test?case=p256-aes128gcm`,
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toMatch(/^ng:/);
    });
  });
});
