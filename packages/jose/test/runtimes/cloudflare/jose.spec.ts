import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Cloudflare Workers", () => {
  describe("Integrated Encryption with HPKE-0 (P-256, AES-128-GCM)", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=integrated-hpke0",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("Integrated Encryption with HPKE-3 (X25519, AES-128-GCM)", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=integrated-hpke3",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("Key Encryption with HPKE-0-KE (P-256, A128GCM content)", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=ke-hpke0",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("Key Encryption with HPKE-3-KE (X25519, A128GCM content)", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=ke-hpke3",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });
});
