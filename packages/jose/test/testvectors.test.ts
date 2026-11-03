/**
 * Test vectors from draft-ietf-jose-hpke-encrypt-22, Appendix A.
 *
 * jose-vectors.json is an unmodified copy of examples/jose-vectors.json at tag
 * draft-ietf-jose-hpke-encrypt-22 of
 * https://github.com/ietf-wg-jose/draft-ietf-jose-hpke-encrypt
 * (SHA-256 235fade8057e5e114d3e6b6e39c7187509178f148e0518a4117e8a3d3c1c3884).
 *
 * The 14 vectors for the algorithms defined by the draft match Appendix A. The
 * file also still has HPKE-4-KE and HPKE-6-KE, which -22 removed from the draft
 * and Appendix A, so they are not used.
 *
 * The draft does not state the plaintext or AAD; the values below were
 * discovered by decryption and by decoding the "aad" member.
 */
import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import type { JoseEncrypt, JoseEncrypt0, JweJson } from "../mod.ts";
import {
  type ContentEncAlg,
  createHpke0,
  createHpke0Ke,
  createHpke1,
  createHpke1Ke,
  createHpke2,
  createHpke2Ke,
  createHpke3,
  createHpke3Ke,
  createHpke4,
  createHpke5,
  createHpke5Ke,
  createHpke6,
  createHpke7,
  createHpke7Ke,
} from "../mod.ts";
import { buildRecipientStructure } from "../src/structures.ts";
import { decodeBase64Url } from "../src/utils.ts";

interface Vector {
  alg: string;
  jwk: JsonWebKey;
  flattened: {
    protected: string;
    aad: string;
    encrypted_key: string;
    ciphertext: string;
    iv?: string;
    tag?: string;
  };
  compact: string;
}

const REMOVED_FROM_DRAFT = new Set(["HPKE-4-KE", "HPKE-6-KE"]);

const allVectors: Vector[] = JSON.parse(
  Deno.readTextFileSync(new URL("./jose-vectors.json", import.meta.url)),
);
const vectors = allVectors.filter((v) => !REMOVED_FROM_DRAFT.has(v.alg));

const INTEGRATED: Record<string, () => JoseEncrypt0> = {
  "HPKE-0": createHpke0,
  "HPKE-1": createHpke1,
  "HPKE-2": createHpke2,
  "HPKE-3": createHpke3,
  "HPKE-4": createHpke4,
  "HPKE-5": createHpke5,
  "HPKE-6": createHpke6,
  "HPKE-7": createHpke7,
};

const KEY_ENCRYPTION: Record<string, (enc: ContentEncAlg) => JoseEncrypt> = {
  "HPKE-0-KE": createHpke0Ke,
  "HPKE-1-KE": createHpke1Ke,
  "HPKE-2-KE": createHpke2Ke,
  "HPKE-3-KE": createHpke3Ke,
  "HPKE-5-KE": createHpke5Ke,
  "HPKE-7-KE": createHpke7Ke,
};

const EXPECTED_PLAINTEXT =
  "You can trust us to stick with you through thick and thin-to the bitter end. " +
  "And you can trust us to keep any secret of yours-closer than you keep it yourself. " +
  "But you cannot trust us to let you face trouble alone, and go off without a word. " +
  "We are your friends, Frodo.";

const EXPECTED_AAD = "The Fellowship of the Ring";

const td = new TextDecoder();

function decodeHeader(encoded: string): Record<string, string> {
  return JSON.parse(td.decode(decodeBase64Url(encoded)));
}

describe("Test vectors from draft-ietf-jose-hpke-encrypt-22", () => {
  it("should load every vector", () => {
    assertEquals(
      vectors.map((v) => v.alg).sort(),
      [...Object.keys(INTEGRATED), ...Object.keys(KEY_ENCRYPTION)].sort(),
    );
  });

  describe("Recipient_structure example (Section 6.1.1)", () => {
    it("should match the expected bytes", () => {
      const actual = Array.from(buildRecipientStructure("A128GCM"))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      assertEquals(actual, "4a4f53452d48504b452072637074ff4131323847434dff");
    });
  });

  for (const v of vectors) {
    describe(v.alg, () => {
      it("should have a protected header for this algorithm", () => {
        assertEquals(decodeHeader(v.flattened.protected).alg, v.alg);
        assertEquals(decodeHeader(v.compact.split(".")[0]).alg, v.alg);
        assertEquals(v.jwk.alg, v.alg);
        assertEquals(td.decode(decodeBase64Url(v.flattened.aad)), EXPECTED_AAD);
      });

      if (v.alg in INTEGRATED) {
        it("should decrypt the Compact Serialization", async () => {
          const enc = INTEGRATED[v.alg]();
          const key = await enc.importPrivateJwk(v.jwk);
          const pt = await enc.open(key, v.compact);
          assertEquals(td.decode(pt), EXPECTED_PLAINTEXT);
        });

        it("should decrypt the Flattened JSON Serialization", async () => {
          const enc = INTEGRATED[v.alg]();
          const key = await enc.importPrivateJwk(v.jwk);
          const pt = await enc.open(key, v.flattened);
          assertEquals(td.decode(pt), EXPECTED_PLAINTEXT);
        });
      } else {
        const contentEncAlg = decodeHeader(v.flattened.protected)
          .enc as ContentEncAlg;

        it("should decrypt the Compact Serialization", async () => {
          const enc = KEY_ENCRYPTION[v.alg](contentEncAlg);
          const key = await enc.importPrivateJwk(v.jwk);
          const pt = await enc.open(key, v.compact);
          assertEquals(td.decode(pt), EXPECTED_PLAINTEXT);
        });

        it("should decrypt the Flattened JSON Serialization", async () => {
          const enc = KEY_ENCRYPTION[v.alg](contentEncAlg);
          const key = await enc.importPrivateJwk(v.jwk);
          const pt = await enc.open(key, v.flattened);
          assertEquals(td.decode(pt), EXPECTED_PLAINTEXT);
        });
      }
    });
  }
});

/**
 * -22 has no General JSON example, so the HPKE-0-KE example from
 * draft-ietf-jose-hpke-encrypt-16 Section 6.3 is kept: it is the only external
 * vector with "ek" in the per-recipient header, which is the form
 * JoseEncrypt.seal() produces.
 */
describe("General JSON example from draft-ietf-jose-hpke-encrypt-16", () => {
  const jwk = {
    kty: "EC",
    use: "enc",
    alg: "HPKE-0-KE",
    kid: "9CfUPiGcAcTp7oXgVbDStw2FEjka-_KHU_i-X3XMCEA",
    crv: "P-256",
    x: "WVKOswXQAgntIrLSYlwkyaU1dIE-FIhrbTEotFgMwIA",
    y: "jpZT1WNmQH752Bh_pDK41IhLkiXLj-15wR4ZBZ-MWFk",
    d: "MeCnMF65SaRVZ11Gf1Weacx3H9SdzO7MtWcDXvHWNv8",
  };

  const jwe: JweJson = {
    ciphertext: "uF1XBbVZWhYm_pDbeJvI_fkuqFJiKd1WMP3O_BAGOP-LkpTLE3Et2VQNcOpP" +
      "AIBfyx8rUzshGqiOFOWzcoWZ3mIwYuDvvAW3-P1RCS8Dtq70JRvahO5O8sAN" +
      "1vzJg8_dyBPnwsQY6Cy3RhMD6sSSCjjSw0FYmmx67IiI2zJ6Wr8z69k0f34Z" +
      "Th43k4C-pTwaUSvjl2XI_YrUgdDVYmY_MJ5vmlPTcceMaefP8Onz_fx5xOcG" +
      "fnVBVz2gpMQPuQL8k5Rk5KJvPGfFfN6hrgWkK_LDzi4lrfnIrvNsk3BCBeZP" +
      "pc-n19-u7W4-GQxLjAlVyMHeGk5K4tU6gHB8PnnQ4ND5ZTtyXrJWQW-Qr1iF" +
      "ev6g",
    iv: "mLiHjYaQA42nPm1L",
    recipients: [
      {
        encrypted_key: "hU6b0hp4-y4ZoK1Qz8YWmDmqDmgTto3HW25-RyPhcLU",
        header: {
          alg: "HPKE-0-KE",
          kid: "9CfUPiGcAcTp7oXgVbDStw2FEjka-_KHU_i-X3XMCEA",
          ek:
            "BGWPWLoD5BUjFEDIjMS-yvtcCXBn5A-kuv2RjzUY_2hKUjgZINqtEy1aHZ8dWxAiyApV5JafG76W8O_yZzy5T54",
        },
      },
    ],
    tag: "K22C64ZhFABEu2S2F00PLg",
    aad: "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
    protected: "eyJlbmMiOiJBMTI4R0NNIn0",
  };

  it("should decrypt using JoseEncrypt.open()", async () => {
    const enc = createHpke0Ke("A128GCM");
    const pt = await enc.open(await enc.importPrivateJwk(jwk), jwe);
    assertEquals(
      td.decode(pt),
      // This example uses U+2013 where the -22 plaintext uses a hyphen.
      EXPECTED_PLAINTEXT.replaceAll("-", "–"),
    );
  });
});
