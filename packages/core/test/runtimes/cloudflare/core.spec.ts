import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Cloudflare Workers", () => {
  describe("GET /test?kem=0x0010", () => {
    it("should return ok", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002"]) {
          const res = await SELF.fetch(
            `https://example.com/test?kem=0x0010&kdf=${kdf}&aead=${aead}`,
          );
          expect(res.status).toBe(200);
          expect(await res.text()).toBe("ok");
        }
      }
    });
  });

  describe("GET /test?kem=0x0011", () => {
    it("should return ok", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002"]) {
          const res = await SELF.fetch(
            `https://example.com/test?kem=0x0011&kdf=${kdf}&aead=${aead}`,
          );
          expect(res.status).toBe(200);
          expect(await res.text()).toBe("ok");
        }
      }
    });
  });

  describe("GET /test?kem=0x0012", () => {
    it("should return ok", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002"]) {
          const res = await SELF.fetch(
            `https://example.com/test?kem=0x0012&kdf=${kdf}&aead=${aead}`,
          );
          expect(res.status).toBe(200);
          expect(await res.text()).toBe("ok");
        }
      }
    });
  });

  describe("GET /test?kem=0x0020", () => {
    it("should return ok", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002"]) {
          const res = await SELF.fetch(
            `https://example.com/test?kem=0x0020&kdf=${kdf}&aead=${aead}`,
          );
          expect(res.status).toBe(200);
          expect(await res.text()).toBe("ok");
        }
      }
    });
  });

  describe("GET /test?kem=0x0021", () => {
    it("should return ok", async () => {
      for (const kdf of ["0x0001", "0x0002", "0x0003"]) {
        for (const aead of ["0x0001", "0x0002"]) {
          const res = await SELF.fetch(
            `https://example.com/test?kem=0x0021&kdf=${kdf}&aead=${aead}`,
          );
          expect(res.status).toBe(200);
          expect(await res.text()).toBe("ok");
        }
      }
    });
  });
});
