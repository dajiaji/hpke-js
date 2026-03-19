import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  ContentEncAlg,
  createHpke0,
  createHpke3,
  createHpke3Ke,
  JoseError,
} from "../mod.ts";

describe("JoseError", () => {
  it("should have the correct name", () => {
    const err = new JoseError("test error");
    assertEquals(err.name, "JoseError");
    assertEquals(err.message, "test error");
  });
});

describe("Integrated Encryption errors", () => {
  it("should reject invalid JWE compact serialization (wrong parts)", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    await assertRejects(
      async () => {
        await enc0.open(rkp, "only.two.parts");
      },
      JoseError,
      "Invalid JWE Compact Serialization",
    );
  });

  it("should reject invalid JWE compact serialization (empty parts)", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    await assertRejects(
      async () => {
        await enc0.open(rkp, ".....");
      },
      JoseError,
    );
  });

  it("should reject invalid protected header (not JSON)", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    await assertRejects(
      async () => {
        await enc0.open(rkp, "bm90LWpzb24.AAAA..AAAA.");
      },
      JoseError,
      "Invalid protected header",
    );
  });

  it("should reject algorithm mismatch", async () => {
    const enc0_hpke0 = createHpke0();
    const enc0_hpke3 = createHpke3();
    const rkp = await enc0_hpke3.suite.kem.generateKeyPair();

    // Seal with HPKE-3, try to open with HPKE-0 instance
    const jwe = await enc0_hpke3.seal(rkp.publicKey, new Uint8Array([1, 2]));

    await assertRejects(
      async () => {
        const rkp0 = await enc0_hpke0.suite.kem.generateKeyPair();
        await enc0_hpke0.open(rkp0, jwe);
      },
      JoseError,
      "Algorithm mismatch",
    );
  });

  it("should reject enc parameter in Integrated Encryption", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    // Manually craft a JWE with "enc" in the header
    const header = btoa(JSON.stringify({ alg: "HPKE-3", enc: "A128GCM" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const jwe = `${header}.AAAA..AAAA.`;

    await assertRejects(
      async () => {
        await enc0.open(rkp, jwe);
      },
      JoseError,
      "enc parameter must not be present",
    );
  });

  it("should reject psk_id present without PSK mode", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    const plaintext = new TextEncoder().encode("psk test");
    const psk = {
      id: "my-psk-id",
      key: crypto.getRandomValues(new Uint8Array(32)),
    };
    const jwe = await enc0.seal(rkp.publicKey, plaintext, { psk });

    await assertRejects(
      async () => {
        // Open without PSK
        await enc0.open(rkp, jwe);
      },
      JoseError,
      "psk_id present but PSK mode was not selected",
    );
  });
});

describe("Key Encryption errors", () => {
  it("should reject empty recipients", async () => {
    const enc = createHpke3Ke(ContentEncAlg.A128GCM);
    await assertRejects(
      async () => {
        await enc.seal([], new Uint8Array([1, 2, 3]));
      },
      JoseError,
      "At least one recipient is required",
    );
  });

  it("should reject missing protected header", async () => {
    const enc = createHpke3Ke(ContentEncAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();

    await assertRejects(
      async () => {
        await enc.open(rkp, {
          protected: "",
          iv: "AAAA",
          ciphertext: "AAAA",
          tag: "AAAA",
          recipients: [],
        });
      },
      JoseError,
      "Missing protected header",
    );
  });

  it("should reject missing recipients array", async () => {
    const enc = createHpke3Ke(ContentEncAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();

    const header = btoa(JSON.stringify({ enc: "A128GCM" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    await assertRejects(
      async () => {
        await enc.open(rkp, {
          protected: header,
          iv: "AAAA",
          ciphertext: "AAAA",
          tag: "AAAA",
          recipients: undefined as unknown as [],
        });
      },
      JoseError,
      "Missing or invalid recipients array",
    );
  });
});
