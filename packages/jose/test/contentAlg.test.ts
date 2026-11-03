import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { ExportOnly } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import {
  type AeadInterface,
  Aes128Gcm,
  Aes256Gcm,
  ContentEncAlg,
  createJoseHpke0Ke,
  createJoseHpke1Ke,
  createJoseHpke2Ke,
  createJoseHpke3Ke,
  createJoseHpke5Ke,
  createJoseHpke7Ke,
  type JoseEncrypt,
  JoseError,
} from "../mod.ts";
import { buildRecipientStructure } from "../src/structures.ts";
import { decodeBase64Url } from "../src/utils.ts";

const FACTORIES: [string, (aead: AeadInterface) => JoseEncrypt][] = [
  ["HPKE-0-KE", createJoseHpke0Ke],
  ["HPKE-1-KE", createJoseHpke1Ke],
  ["HPKE-2-KE", createJoseHpke2Ke],
  ["HPKE-3-KE", createJoseHpke3Ke],
  ["HPKE-5-KE", createJoseHpke5Ke],
  ["HPKE-7-KE", createJoseHpke7Ke],
];
const CONTENT_AEADS: [() => AeadInterface, ContentEncAlg, number][] = [
  [() => new Aes128Gcm(), ContentEncAlg.A128GCM, 16],
  [() => new Aes256Gcm(), ContentEncAlg.A256GCM, 32],
];
function ab(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

describe("JoseEncrypt content algorithm", () => {
  for (const [name, factory] of FACTORIES) {
    for (const [createAead, contentAlg, keySize] of CONTENT_AEADS) {
      it(`${name} encrypts content with ${contentAlg} as labeled`, async () => {
        const enc = factory(createAead());
        const rkp = await enc.generateKemKeyPair();
        const plaintext = new TextEncoder().encode(`${name}/${contentAlg}`);
        const aad = new TextEncoder().encode("independent content decryption");
        const jwe = await enc.seal(
          [{ recipientPublicKey: rkp.publicKey }],
          plaintext,
          { aad },
        );
        const header = JSON.parse(
          new TextDecoder().decode(decodeBase64Url(jwe.protected)),
        );
        assertEquals(header.enc, contentAlg);
        const recipient = jwe.recipients[0];
        assertEquals(recipient.header.alg, name);
        // Unwrap with raw HPKE and decrypt with WebCrypto independently
        // of the content AEAD selected by the library.
        const ctx = await enc.suite.createRecipientContext({
          recipientKey: rkp.privateKey,
          enc: decodeBase64Url(recipient.header.ek as string),
          info: buildRecipientStructure(contentAlg),
        });
        const cek = new Uint8Array(
          await ctx.open(decodeBase64Url(recipient.encrypted_key)),
        );
        assertEquals(cek.length, keySize);
        const key = await crypto.subtle.importKey(
          "raw",
          ab(cek),
          "AES-GCM",
          false,
          ["decrypt"],
        );
        const ct = decodeBase64Url(jwe.ciphertext);
        const tag = decodeBase64Url(jwe.tag!);
        assertEquals(tag.length, 16);
        const combined = new Uint8Array(ct.length + tag.length);
        combined.set(ct);
        combined.set(tag, ct.length);
        const independentPlaintext = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: ab(decodeBase64Url(jwe.iv!)),
            additionalData: ab(
              new TextEncoder().encode(`${jwe.protected}.${jwe.aad}`),
            ),
            tagLength: 128,
          },
          key,
          ab(combined),
        );
        assertEquals(new Uint8Array(independentPlaintext), plaintext);
        assertEquals(await enc.open(rkp, jwe), plaintext);
      });
    }
    for (const aead of [new ExportOnly(), new Chacha20Poly1305()]) {
      it(`${name} rejects unsupported content AEAD ${aead.id}`, () => {
        assertThrows(
          () => factory(aead),
          JoseError,
          "Unsupported content encryption AEAD",
        );
      });
    }
  }
  for (const [createAead, contentAlg] of CONTENT_AEADS) {
    for (const field of ["keySize", "nonceSize", "tagSize"] as const) {
      it(`rejects ${contentAlg} with inconsistent ${field}`, () => {
        const inner = createAead();
        const aead: AeadInterface = {
          id: inner.id,
          keySize: inner.keySize,
          nonceSize: inner.nonceSize,
          tagSize: inner.tagSize,
          createEncryptionContext: (key) => inner.createEncryptionContext(key),
          [field]: inner[field] + 1,
        };
        assertThrows(
          () => createJoseHpke3Ke(aead),
          JoseError,
          "Invalid content encryption AEAD parameters",
        );
      });
    }
  }
  it("uses the supplied AEAD instance for both seal and open", async () => {
    const inner = new Aes256Gcm();
    let seals = 0;
    let opens = 0;
    const aead: AeadInterface = {
      id: inner.id,
      keySize: inner.keySize,
      nonceSize: inner.nonceSize,
      tagSize: inner.tagSize,
      createEncryptionContext(key) {
        const ctx = inner.createEncryptionContext(key);
        return {
          seal(iv, data, aad) {
            seals++;
            return ctx.seal(iv, data, aad);
          },
          open(iv, data, aad) {
            opens++;
            return ctx.open(iv, data, aad);
          },
        };
      },
    };
    const enc = createJoseHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();
    const plaintext = new Uint8Array([1, 2, 3]);
    const jwe = await enc.seal(
      [{ recipientPublicKey: rkp.publicKey }],
      plaintext,
    );
    assertEquals(await enc.open(rkp, jwe), plaintext);
    assertEquals(seals, 1);
    assertEquals(opens, 1);
  });
});
