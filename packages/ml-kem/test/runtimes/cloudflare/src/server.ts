import type { AeadInterface, KdfInterface, KemInterface } from "@hpke/core";

import {
  AeadId,
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  ExportOnly,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
  KdfId,
  KemId,
} from "@hpke/core";

import { MlKem1024, MlKem512, MlKem768 } from "@hpke/ml-kem";

function createKem(id: number): KemInterface {
  switch (id) {
    case KemId.MlKem512:
      return new MlKem512();
    case KemId.MlKem768:
      return new MlKem768();
    case KemId.MlKem1024:
      return new MlKem1024();
    default:
      break;
  }
  throw new Error("ng: invalid kdf");
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

function createAead(id: number): AeadInterface {
  switch (id) {
    case AeadId.Aes128Gcm:
      return new Aes128Gcm();
    case AeadId.Aes256Gcm:
      return new Aes256Gcm();
    case AeadId.ExportOnly:
      return new ExportOnly();
    default:
      break;
  }
  throw new Error("ng: invalid aead");
}

export async function testServer(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== "/test") {
    return new Response("ng: invalid path");
  }
  const params = url.searchParams;
  const kemStr = params.get("kem");
  const kdfStr = params.get("kdf");
  const aeadStr = params.get("aead");
  if (kemStr === null || kdfStr === null || aeadStr === null) {
    return new Response("ng: invalid params");
  }
  const kem = Number.parseInt(kemStr);
  const kdf = Number.parseInt(kdfStr);
  const aead = Number.parseInt(aeadStr);
  if (Number.isNaN(kdf) || Number.isNaN(aead)) {
    return new Response("ng: invalid params");
  }

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
    const ct = await sender.seal(new TextEncoder().encode("hello world!"));
    const pt = await recipient.open(ct);
    if ("hello world!" !== new TextDecoder().decode(pt)) {
      return new Response("ng");
    }
  } catch (e: unknown) {
    return new Response("ng: " + (e as Error).message);
  }
  return new Response("ok");
}
