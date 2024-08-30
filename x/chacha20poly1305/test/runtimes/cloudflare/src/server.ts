import {
  CipherSuite,
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
  KdfId,
  KemId,
} from "@hpke/core";

import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

function createKem(id) {
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

function createKdf(id) {
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

export async function testServer(request) {
  const url = new URL(request.url);
  if (url.pathname !== "/test") {
    return new Response("ng: invalid path");
  }
  const params = url.searchParams;
  const kemStr = params.get("kem");
  const kdfStr = params.get("kdf");
  if (kemStr === null || kdfStr === null) {
    return new Response("ng: invalid params");
  }
  const kem = Number.parseInt(kemStr);
  const kdf = Number.parseInt(kdfStr);
  const aead = new Chacha20Poly1305();
  if (Number.isNaN(kem) || Number.isNaN(kdf)) {
    return new Response("ng: invalid params");
  }

  try {
    const suite = new CipherSuite({
      kem: createKem(kem),
      kdf: createKdf(kdf),
      aead: aead,
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
  } catch (e) {
    return new Response("ng: " + e.message);
  }
  return new Response("ok");
}
