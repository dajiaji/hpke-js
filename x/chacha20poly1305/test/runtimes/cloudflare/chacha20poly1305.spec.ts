import { assertEquals } from "testing/asserts.ts";
import { describe, it } from "testing/bdd.ts";

describe("Cloudflare Workers", () => {
  describe("GET /test", () => {
    it("should return ok", async () => {
      for (const kem of ["0x0010", "0x0011", "0x0012"]) {
        for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
          const res = await fetch(
            `http://localhost:8792/test?kem=${kem}&kdf=${kdf}`,
          );
          assertEquals("ok", await res.text());
        }
      }
    });
  });
});
