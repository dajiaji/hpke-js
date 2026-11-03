import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { ExportOnly } from "@hpke/core";

import {
  type AeadInterface,
  Aes128Gcm,
  Aes256Gcm,
  Chacha20Poly1305,
  ContentAlg,
  type CoseEncrypt,
  CoseError,
  createHpke0Ke,
  createHpke1Ke,
  createHpke2Ke,
  createHpke3Ke,
  createHpke4Ke,
  createHpke5Ke,
  createHpke6Ke,
  createHpke7Ke,
} from "../mod.ts";
import { decode } from "../src/cbor/decoder.ts";
import {
  buildEncStructureEncrypt,
  buildRecipientStructure,
  HeaderLabel,
} from "../src/structures.ts";

const FACTORIES: [string, (aead: AeadInterface) => CoseEncrypt][] = [
  ["HPKE-0-KE", createHpke0Ke],
  ["HPKE-1-KE", createHpke1Ke],
  ["HPKE-2-KE", createHpke2Ke],
  ["HPKE-3-KE", createHpke3Ke],
  ["HPKE-4-KE", createHpke4Ke],
  ["HPKE-5-KE", createHpke5Ke],
  ["HPKE-6-KE", createHpke6Ke],
  ["HPKE-7-KE", createHpke7Ke],
];

// Every content AEAD must be usable with every HPKE-X-KE suite: the Layer 0
// algorithm is independent of the AEAD used for key wrapping.
const CONTENT_AEADS: [string, () => AeadInterface, ContentAlg][] = [
  ["Aes128Gcm", () => new Aes128Gcm(), ContentAlg.A128GCM],
  ["Aes256Gcm", () => new Aes256Gcm(), ContentAlg.A256GCM],
  [
    "Chacha20Poly1305",
    () => new Chacha20Poly1305(),
    ContentAlg.CHACHA20POLY1305,
  ],
];

function ab(u: Uint8Array): ArrayBuffer {
  return (u.buffer as ArrayBuffer).slice(
    u.byteOffset,
    u.byteOffset + u.byteLength,
  );
}

/**
 * Decrypt Layer 0 independently of the library's content crypto selection:
 * unwrap the CEK with raw HPKE, then decrypt with a cipher chosen solely
 * from the alg value in the protected header.
 */
async function independentOpen(
  enc: CoseEncrypt,
  rkp: CryptoKeyPair,
  data: Uint8Array,
): Promise<{ alg: unknown; plaintext: Uint8Array }> {
  const [protectedHeader, unprotected, ciphertext, recipients] = decode(
    data,
  ) as [Uint8Array, Map<unknown, unknown>, Uint8Array, unknown[][]];
  const alg = (decode(protectedHeader) as Map<unknown, unknown>).get(
    HeaderLabel.ALG,
  );
  const nonce = unprotected.get(HeaderLabel.IV) as Uint8Array;

  const [rProtected, rUnprotected, wrapped] = recipients[0] as [
    Uint8Array,
    Map<unknown, unknown>,
    Uint8Array,
  ];
  const ctx = await enc.suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: rUnprotected.get(HeaderLabel.EK) as Uint8Array,
    info: buildRecipientStructure(
      alg as number,
      rProtected,
      new Uint8Array(0),
    ),
  });
  const cek = new Uint8Array(await ctx.open(wrapped));
  const aad = buildEncStructureEncrypt(protectedHeader, new Uint8Array(0));

  let plaintext: Uint8Array;
  if (alg === ContentAlg.CHACHA20POLY1305) {
    const c = new Chacha20Poly1305().createEncryptionContext(cek);
    plaintext = new Uint8Array(await c.open(nonce, ciphertext, aad));
  } else {
    const key = await crypto.subtle.importKey(
      "raw",
      ab(cek),
      "AES-GCM",
      false,
      [
        "decrypt",
      ],
    );
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ab(nonce), additionalData: ab(aad) },
        key,
        ab(ciphertext),
      ),
    );
  }
  return { alg, plaintext };
}

describe("CoseEncrypt content algorithm", () => {
  for (const [name, factory] of FACTORIES) {
    for (const [aeadName, createAead, contentAlg] of CONTENT_AEADS) {
      it(`${name} encrypts Layer 0 with ${aeadName} as labeled`, async () => {
        const enc = factory(createAead());
        const rkp = await enc.generateKemKeyPair();
        const plaintext = new TextEncoder().encode(`${name}/${aeadName}`);

        const ct = await enc.seal(
          [{ recipientPublicKey: rkp.publicKey }],
          plaintext,
        );

        const res = await independentOpen(enc, rkp, ct);
        assertEquals(res.alg, contentAlg);
        assertEquals(res.plaintext, plaintext);
        assertEquals(await enc.open(rkp, ct), plaintext);
      });
    }

    it(`${name} rejects an Export-Only AEAD at construction`, () => {
      assertThrows(
        () => factory(new ExportOnly()),
        CoseError,
        "Unsupported content encryption AEAD: id=0xffff",
      );
    });
  }
});
