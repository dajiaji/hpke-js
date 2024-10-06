import { expect, test } from "bun:test";

import {
  AeadId,
  AeadInterface,
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  ExportOnly,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
  KdfId,
  KdfInterface,
} from "@hpke/core";

import { DhkemSecp256k1HkdfSha256 } from "@hpke/dhkem-secp256k1";

function createKdf(id: number): KdfInterface {
  switch (id) {
    case KdfId.HkdfSha256:
      return new HkdfSha256();
    case KdfId.HkdfSha384:
      return new HkdfSha384();
    case KdfId.HkdfSha512:
      return new HkdfSha512();
    default:
      break;
  }
  throw new Error("ng: invalid kdf");
}

function createAead(id: number): AeadInterface {
  switch (id) {
    case AeadId.Aes128Gcm:
      return new Aes128Gcm();
    case AeadId.Aes256Gcm:
      return new Aes256Gcm();
    // case AeadId.Chacha20Poly1305:
    //   return new Chacha20Poly1305();
    case AeadId.ExportOnly:
      return new ExportOnly();
    default:
      break;
  }
  throw new Error("ng: invalid aead");
}

test("bun - normal cases", async () => {
  const kem = new DhkemSecp256k1HkdfSha256();
  for (const kdf of [0x0001, 0x0002, 0x0003]) {
    for (const aead of [0x0001, 0x0002]) {
      try {
        const suite = new CipherSuite({
          kem: kem,
          kdf: createKdf(kdf),
          aead: createAead(aead),
        });
        const rkp = await suite.kem.generateKeyPair();
        const sender = await suite.createSenderContext({
          recipientPublicKey: rkp.publicKey,
        });
        const recipient = await suite.createRecipientContext({
          recipientKey: rkp,
          enc: sender.enc,
        });
        const ct = await sender.seal(new TextEncoder().encode("hello world!"));
        const pt = await recipient.open(ct);
        expect(new TextDecoder().decode(pt)).toBe("hello world!");
      } catch (e: unknown) {
        expect().fail("ng: " + (e as Error).message);
      }
    }
  }
});
