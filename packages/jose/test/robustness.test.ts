import { assertEquals, assertRejects, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  type AeadInterface,
  Aes128Gcm,
  Aes256Gcm,
  createJoseHpke0,
  createJoseHpke3Ke,
  JoseError,
  type JweJson,
} from "../mod.ts";
import { buildRecipientStructure } from "../src/structures.ts";
import { decodeBase64Url, encodeBase64Url } from "../src/utils.ts";

const PLAINTEXT = new TextEncoder().encode("robustness");

function recordingAead(failSeal?: Error, failCreate?: Error) {
  const inner = new Aes128Gcm();
  const keys: Uint8Array[] = [];
  const aead: AeadInterface = {
    id: inner.id,
    keySize: inner.keySize,
    nonceSize: inner.nonceSize,
    tagSize: inner.tagSize,
    createEncryptionContext(key) {
      keys.push(key as Uint8Array);
      if (failCreate) throw failCreate;
      const ctx = inner.createEncryptionContext(key);
      return {
        seal: (iv, data, aad) =>
          failSeal ? Promise.reject(failSeal) : ctx.seal(iv, data, aad),
        open: (iv, data, aad) => ctx.open(iv, data, aad),
      };
    },
  };
  return { aead, keys };
}

function assertCleared(keys: Uint8Array[], count: number) {
  assertEquals(keys.length, count);
  for (const key of keys) assertEquals(key, new Uint8Array(key.length));
}

describe("Key Encryption error handling and CEK zeroization", () => {
  it("clears the CEK after seal and open", async () => {
    const { aead, keys } = recordingAead();
    const enc = createJoseHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();
    const jwe = await enc.seal(
      [{ recipientPublicKey: rkp.publicKey }],
      PLAINTEXT,
    );
    assertEquals(await enc.open(rkp, jwe), PLAINTEXT);
    assertCleared(keys, 2);
  });

  it("wraps a content decryption failure and clears the CEK", async () => {
    const { aead, keys } = recordingAead();
    const enc = createJoseHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();
    const jwe = await enc.seal(
      [{ recipientPublicKey: rkp.publicKey }],
      PLAINTEXT,
    );
    const ct = decodeBase64Url(jwe.ciphertext);
    ct[0] ^= 1;
    jwe.ciphertext = encodeBase64Url(ct);
    const err = await assertRejects(
      () => enc.open(rkp, jwe),
      JoseError,
      "Content decryption failed",
    );
    assertEquals(err.cause instanceof Error, true);
    assertCleared(keys, 2);
  });

  it("wraps a content encryption failure and clears the CEK", async () => {
    const original = new Error("injected seal failure");
    const { aead, keys } = recordingAead(original);
    const enc = createJoseHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();
    const err = await assertRejects(
      () => enc.seal([{ recipientPublicKey: rkp.publicKey }], PLAINTEXT),
      JoseError,
      "Encryption failed",
    );
    assertStrictEquals(err.cause, original);
    assertCleared(keys, 1);
  });

  it("clears the CEK if creating a content context throws", async () => {
    const original = new Error("injected context failure");
    const { aead, keys } = recordingAead(undefined, original);
    const enc = createJoseHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();
    const err = await assertRejects(
      () => enc.seal([{ recipientPublicKey: rkp.publicKey }], PLAINTEXT),
      JoseError,
      "Encryption failed",
    );
    assertStrictEquals(err.cause, original);
    assertCleared(keys, 1);
  });

  it("wraps a recipient wrapping failure and clears the CEK", async () => {
    const { aead, keys } = recordingAead();
    const enc = createJoseHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();
    const incompatible = await createJoseHpke0().generateKemKeyPair();
    const err = await assertRejects(
      () =>
        enc.seal([
          { recipientPublicKey: rkp.publicKey },
          { recipientPublicKey: incompatible.publicKey },
        ], PLAINTEXT),
      JoseError,
      "Encryption failed",
    );
    assertEquals(err.cause instanceof Error, true);
    assertCleared(keys, 1);
  });

  it("preserves an existing JoseError", async () => {
    const original = new JoseError("existing error");
    const { aead, keys } = recordingAead(original);
    const enc = createJoseHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();
    const err = await assertRejects(
      () => enc.seal([{ recipientPublicKey: rkp.publicKey }], PLAINTEXT),
      JoseError,
    );
    assertStrictEquals(err, original);
    assertCleared(keys, 1);
  });
});

describe("Unwrapped CEK length validation", () => {
  for (
    const [contentAead, actualKeySize] of [
      [new Aes256Gcm(), 16],
      [new Aes128Gcm(), 32],
      [new Aes128Gcm(), 24],
    ] as const
  ) {
    it(`rejects ${actualKeySize} bytes when ${contentAead.keySize} are required and clears the CEK`, async () => {
      const enc = createJoseHpke3Ke(contentAead);
      const rkp = await enc.generateKemKeyPair();
      const contentAlg = contentAead.keySize === 16 ? "A128GCM" : "A256GCM";
      const cek = crypto.getRandomValues(new Uint8Array(actualKeySize));
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const protectedHeader = encodeBase64Url(
        new TextEncoder().encode(JSON.stringify({ enc: contentAlg })),
      );
      // This ciphertext authenticates successfully with WebCrypto, despite
      // using a different AES key length from the one advertised by enc.
      const key = await crypto.subtle.importKey(
        "raw",
        cek.buffer,
        "AES-GCM",
        false,
        ["encrypt"],
      );
      const combined = new Uint8Array(
        await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: nonce,
            additionalData: new TextEncoder().encode(protectedHeader),
          },
          key,
          PLAINTEXT,
        ),
      );
      const sender = await enc.suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        info: buildRecipientStructure(contentAlg),
      });
      const jwe: JweJson = {
        protected: protectedHeader,
        iv: encodeBase64Url(nonce),
        ciphertext: encodeBase64Url(combined.slice(0, -16)),
        tag: encodeBase64Url(combined.slice(-16)),
        recipients: [{
          header: {
            alg: "HPKE-3-KE",
            ek: encodeBase64Url(new Uint8Array(sender.enc)),
          },
          encrypted_key: encodeBase64Url(
            new Uint8Array(await sender.seal(cek)),
          ),
        }],
      };
      // Observe the actual plaintext buffer returned by HPKE to verify that
      // even a rejected CEK is cleared before open() returns.
      let unwrapped: Uint8Array | undefined;
      const createContext = enc.suite.createRecipientContext.bind(enc.suite);
      enc.suite.createRecipientContext = async (params) => {
        const ctx = await createContext(params);
        const open = ctx.open.bind(ctx);
        ctx.open = async (data, aad) => {
          const result = await open(data, aad);
          unwrapped = new Uint8Array(result);
          return result;
        };
        return ctx;
      };
      await assertRejects(
        () => enc.open(rkp, jwe),
        JoseError,
        "Invalid CEK length",
      );
      assertEquals(unwrapped, new Uint8Array(actualKeySize));
    });
  }
});
