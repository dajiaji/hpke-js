import { assertEquals } from "testing/asserts.ts";
import { describe, it } from "testing/bdd.ts";

describe("Cloudflare Workers", () => {
  describe("GET /test?kem=0x0020", () => {
    it("should return ok", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002", "0x0003"]) {
          const res = await fetch(
            `http://localhost:8787/test?kem=0x0020&kdf=${kdf}&aead=${aead}`,
          );
          assertEquals("ok", await res.text());
        }
      }
    });
  });

  describe("GET /test?kem=0x0021", () => {
    it("should return ok", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002", "0x0003"]) {
          const res = await fetch(
            `http://localhost:8787/test?kem=0x0021&kdf=${kdf}&aead=${aead}`,
          );
          assertEquals("ok", await res.text());
        }
      }
    });
  });
});
