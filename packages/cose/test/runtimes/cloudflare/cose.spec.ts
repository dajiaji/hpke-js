import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Cloudflare Workers", () => {
  describe("Encrypt0 with HPKE-0 (P-256, AES-128-GCM)", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=encrypt0-hpke0",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("Encrypt0 with HPKE-3 (X25519, AES-128-GCM)", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=encrypt0-hpke3",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("KE with HPKE-0-KE (P-256, A128GCM content)", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=ke-hpke0",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("KE with HPKE-3-KE (X25519, A128GCM content)", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch(
        "https://example.com/test?case=ke-hpke3",
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });
});
