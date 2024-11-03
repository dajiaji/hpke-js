import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Cloudflare Workers", () => {
  describe("GET /test", () => {
    it("should return ok", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002"]) {
          const res = await SELF.fetch(
            `https://example.com/test?kdf=${kdf}&aead=${aead}`,
          );
          expect(res.status).toBe(200);
          expect(await res.text()).toBe("ok");
        }
      }
    });
  });
});
