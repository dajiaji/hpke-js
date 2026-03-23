import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Cloudflare Workers", () => {
  describe("OHTTP with X25519/AES-128-GCM", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=x25519-aes128gcm",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("OHTTP with X25519/AES-256-GCM", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=x25519-aes256gcm",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("OHTTP with P-256/AES-128-GCM", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=p256-aes128gcm",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });
});
