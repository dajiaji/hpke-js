import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  ContentEncAlg,
  createJoseHpke0,
  createJoseHpke3,
  createJoseHpke3Ke,
  JoseError,
  JoseHpkeAlg,
} from "../mod.ts";
import { buildRecipientStructure } from "../src/structures.ts";
import { encodeBase64Url } from "../src/utils.ts";

const te = new TextEncoder();

function encodeHeader(header: Record<string, unknown>): string {
  return encodeBase64Url(te.encode(JSON.stringify(header)));
}

describe("JoseHpkeAlg", () => {
  it("should not define algorithms removed from the draft", () => {
    const algs: string[] = Object.values(JoseHpkeAlg);
    assertEquals(algs.length, 14);
    assertEquals(algs.includes("HPKE-4-KE"), false);
    assertEquals(algs.includes("HPKE-6-KE"), false);
  });
});

describe("JoseError", () => {
  it("should have the correct name", () => {
    const err = new JoseError("test error");
    assertEquals(err.name, "JoseError");
    assertEquals(err.message, "test error");
  });
});

describe("Integrated Encryption errors", () => {
  it("should reject invalid JWE compact serialization (wrong parts)", async () => {
    const enc0 = createJoseHpke3();
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
    const enc0 = createJoseHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    await assertRejects(
      async () => {
        await enc0.open(rkp, ".....");
      },
      JoseError,
    );
  });

  it("should reject invalid protected header (not JSON)", async () => {
    const enc0 = createJoseHpke3();
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
    const enc0_hpke0 = createJoseHpke0();
    const enc0_hpke3 = createJoseHpke3();
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
    const enc0 = createJoseHpke3();
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
    const enc0 = createJoseHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    const plaintext = new TextEncoder().encode("psk test");
    const psk = {
      id: new TextEncoder().encode("my-psk-id"),
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

describe("Integrated Encryption JSON Serialization errors", () => {
  const base = { encrypted_key: "AAAA", ciphertext: "AAAA" };
  const protectedHeader = encodeHeader({ alg: "HPKE-3" });

  const cases: [
    string,
    Parameters<ReturnType<typeof createJoseHpke3>["open"]>[1],
    string,
  ][] = [
    [
      "alg only in the unprotected header",
      {
        ...base,
        protected: encodeHeader({ kid: "k" }),
        unprotected: { alg: "HPKE-3" },
      },
      "Algorithm mismatch",
    ],
    [
      "enc in the unprotected header",
      { ...base, protected: protectedHeader, unprotected: { enc: "A128GCM" } },
      "enc parameter must not be present",
    ],
    [
      "ek in the per-recipient header",
      { ...base, protected: protectedHeader, header: { ek: "AAAA" } },
      "ek parameter must not be present",
    ],
    [
      "a non-empty iv",
      { ...base, protected: protectedHeader, iv: "AAAA" },
      "iv and tag must be empty",
    ],
    [
      "a non-empty tag",
      { ...base, protected: protectedHeader, tag: "AAAA" },
      "iv and tag must be empty",
    ],
    [
      "no encrypted key",
      { protected: protectedHeader, ciphertext: "AAAA" },
      "Missing encrypted key or ciphertext",
    ],
    [
      "more than one recipient",
      {
        protected: protectedHeader,
        ciphertext: "AAAA",
        recipients: [{ encrypted_key: "AAAA" }, { encrypted_key: "AAAA" }],
      },
      "exactly one recipient",
    ],
    [
      "duplicate Header Parameter names",
      { ...base, protected: protectedHeader, header: { alg: "HPKE-3" } },
      "Duplicate Header Parameter: alg",
    ],
    [
      "both recipients and encrypted_key",
      {
        ...base,
        protected: protectedHeader,
        recipients: [{ encrypted_key: "AAAA" }],
      },
      "recipients must not be used with",
    ],
    [
      "a protected header that is not an object",
      { ...base, protected: encodeBase64Url(te.encode("null")) },
      "Invalid protected header",
    ],
  ];

  for (const [name, jwe, message] of cases) {
    it(`should reject ${name}`, async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();
      await assertRejects(() => enc0.open(rkp, jwe), JoseError, message);
    });
  }

  it("should reject psk_id outside the protected header in PSK mode", async () => {
    const enc0 = createJoseHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();
    const id = te.encode("id");
    const key = new Uint8Array(32);
    await assertRejects(
      () =>
        enc0.open(rkp, {
          ...base,
          protected: protectedHeader,
          header: { psk_id: encodeBase64Url(id) },
        }, { psk: { id, key } }),
      JoseError,
      "Missing psk_id in protected header",
    );
  });

  it("should not treat __proto__ in a header as inherited parameters", async () => {
    const enc0 = createJoseHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();
    const pt = new Uint8Array([1, 2, 3]);
    const compact = await enc0.seal(rkp.publicKey, pt);
    const [protectedPart, encryptedKey, , ciphertext] = compact.split(".");
    // If "__proto__" set the prototype of the JOSE Header, "enc" would appear
    // to be present and this JWE would be rejected.
    const opened = await enc0.open(rkp, {
      protected: protectedPart,
      unprotected: JSON.parse('{"__proto__":{"enc":"A128GCM"}}'),
      encrypted_key: encryptedKey,
      ciphertext,
    });
    assertEquals(opened, pt);
  });
});

describe("Key Encryption errors", () => {
  it("should reject a missing iv or tag", async () => {
    const enc = createJoseHpke3Ke(ContentEncAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();
    const jwe = await enc.seal(
      [{ recipientPublicKey: rkp.publicKey }],
      new Uint8Array([1]),
    );
    const { iv: _iv, ...withoutIv } = jwe;
    const { tag: _tag, ...withoutTag } = jwe;
    await assertRejects(
      () => enc.open(rkp, withoutIv),
      JoseError,
      "Missing IV",
    );
    await assertRejects(
      () => enc.open(rkp, withoutTag),
      JoseError,
      "Missing authentication tag",
    );
  });

  it("should reject a missing or mismatched enc", async () => {
    const enc = createJoseHpke3Ke(ContentEncAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();
    for (const header of [{}, { enc: "A256GCM" }]) {
      await assertRejects(
        () =>
          enc.open(rkp, {
            protected: encodeHeader(header),
            iv: "AAAA",
            ciphertext: "AAAA",
            tag: "AAAA",
            recipients: [{ header: { alg: "HPKE-3-KE", ek: "AAAA" } }],
          }),
        JoseError,
        "Content encryption algorithm mismatch",
      );
    }
  });

  it("should not match a recipient without alg", async () => {
    const enc = createJoseHpke3Ke(ContentEncAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();
    const jwe = await enc.seal(
      [{ recipientPublicKey: rkp.publicKey }],
      new Uint8Array([1]),
    );
    const { alg: _alg, ...header } = jwe.recipients[0].header;
    await assertRejects(
      () =>
        enc.open(rkp, {
          ...jwe,
          recipients: [{ ...jwe.recipients[0], header }],
        }),
      JoseError,
      "No matching recipient",
    );
  });

  it("should reject the same Header Parameter in two header parts", async () => {
    const enc = createJoseHpke3Ke(ContentEncAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();
    const jwe = await enc.seal(
      [{ recipientPublicKey: rkp.publicKey }],
      new Uint8Array([1]),
    );
    await assertRejects(
      () =>
        enc.open(rkp, {
          ...jwe,
          recipients: [{
            ...jwe.recipients[0],
            header: { ...jwe.recipients[0].header, enc: "A128GCM" },
          }],
        }),
      JoseError,
      "Duplicate Header Parameter: enc",
    );
  });

  it("should reject empty recipients", async () => {
    const enc = createJoseHpke3Ke(ContentEncAlg.A128GCM);
    await assertRejects(
      async () => {
        await enc.seal([], new Uint8Array([1, 2, 3]));
      },
      JoseError,
      "At least one recipient is required",
    );
  });

  it("should reject missing protected header", async () => {
    const enc = createJoseHpke3Ke(ContentEncAlg.A128GCM);
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
    const enc = createJoseHpke3Ke(ContentEncAlg.A128GCM);
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

describe('Empty "aad" member', () => {
  const plaintext = te.encode("empty aad");

  describe("Integrated Encryption", () => {
    it("should not authenticate a JWE that had no JWE AAD", async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();
      const [encodedHeader, ek, , ct] = (await enc0.seal(
        rkp.publicKey,
        plaintext,
      )).split(".");
      const jwe = {
        protected: encodedHeader,
        encrypted_key: ek,
        ciphertext: ct,
      };

      assertEquals(await enc0.open(rkp, jwe), plaintext);
      await assertRejects(() => enc0.open(rkp, { ...jwe, aad: "" }));
    });

    it("should use a trailing '.' in the AAD", async () => {
      const enc0 = createJoseHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();
      const encodedHeader = encodeHeader({ alg: "HPKE-3" });
      const ctx = await enc0.suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });
      const ct = await ctx.seal(plaintext, te.encode(`${encodedHeader}.`));
      const jwe = {
        protected: encodedHeader,
        encrypted_key: encodeBase64Url(new Uint8Array(ctx.enc)),
        ciphertext: encodeBase64Url(new Uint8Array(ct)),
      };

      assertEquals(await enc0.open(rkp, { ...jwe, aad: "" }), plaintext);
      await assertRejects(() => enc0.open(rkp, jwe));
    });
  });

  describe("Key Encryption", () => {
    it("should not authenticate a JWE that had no JWE AAD", async () => {
      const enc = createJoseHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
      );

      assertEquals(await enc.open(rkp, jwe), plaintext);
      await assertRejects(() => enc.open(rkp, { ...jwe, aad: "" }));
    });

    it("should omit the member when seal() is given an empty aad", async () => {
      const enc = createJoseHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();
      const jwe = await enc.seal(
        [{ recipientPublicKey: rkp.publicKey }],
        plaintext,
        { aad: new Uint8Array(0) },
      );

      assertEquals("aad" in jwe, false);
      assertEquals(await enc.open(rkp, jwe), plaintext);
    });

    it("should use a trailing '.' in the AAD", async () => {
      const enc = createJoseHpke3Ke(ContentEncAlg.A128GCM);
      const rkp = await enc.generateKemKeyPair();
      const encodedHeader = encodeHeader({ enc: "A128GCM" });

      // Encrypt directly so that seal() is not what open() is checked against.
      const cek = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const combined = new Uint8Array(
        await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv,
            additionalData: te.encode(`${encodedHeader}.`),
          },
          await crypto.subtle.importKey("raw", cek, "AES-GCM", false, [
            "encrypt",
          ]),
          plaintext,
        ),
      );
      // HPKE-3 and HPKE-3-KE use the same HPKE ciphersuite.
      const ctx = await createJoseHpke3().suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        info: buildRecipientStructure("A128GCM"),
      });
      const wrappedCek = await ctx.seal(cek, new Uint8Array(0));
      const jwe = {
        protected: encodedHeader,
        iv: encodeBase64Url(iv),
        ciphertext: encodeBase64Url(combined.slice(0, -16)),
        tag: encodeBase64Url(combined.slice(-16)),
        recipients: [{
          header: {
            alg: "HPKE-3-KE",
            ek: encodeBase64Url(new Uint8Array(ctx.enc)),
          },
          encrypted_key: encodeBase64Url(new Uint8Array(wrappedCek)),
        }],
      };

      assertEquals(await enc.open(rkp, { ...jwe, aad: "" }), plaintext);
      await assertRejects(() => enc.open(rkp, jwe));
    });
  });
});
