import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

describe("Cloudflare Workers", () => {
  describe("GET /test", () => {
    it("should return ok", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002"]) {
          const res = await fetch(
            `http://localhost:8791/test?kdf=${kdf}&aead=${aead}`,
          );
          assertEquals("ok", await res.text());
        }
      }
    });
  });
});
