import { expect, test } from "bun:test";

import type { AeadInterface, KdfInterface, KemInterface } from "@hpke/core";

import {
  AeadId,
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  // ExportOnly,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
  KdfId,
  KemId,
} from "@hpke/core";

function createKem(id: number): KemInterface {
  switch (id) {
    case KemId.DhkemP256HkdfSha256:
      return new DhkemP256HkdfSha256();
    case KemId.DhkemP384HkdfSha384:
      return new DhkemP384HkdfSha384();
    case KemId.DhkemP521HkdfSha512:
      return new DhkemP521HkdfSha512();
    default:
      break;
  }
  throw new Error("ng: invalid kem");
}

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

function createAead(id: AeadId): AeadInterface {
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
  for (const kem of [0x0010, 0x0011, 0x0012]) {
    for (const kdf of [0x0001, 0x0002, 0x0003]) {
      for (const aead of [0x0001, 0x0002]) {
        try {
          const suite = new CipherSuite({
            kem: createKem(kem),
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
          const ct = await sender.seal(
            new TextEncoder().encode("hello world!"),
          );
          const pt = await recipient.open(ct);
          expect(new TextDecoder().decode(pt)).toBe("hello world!");
        } catch (e: unknown) {
          expect().fail("ng: " + (e as Error).message);
        }
      }
    }
  }
});
