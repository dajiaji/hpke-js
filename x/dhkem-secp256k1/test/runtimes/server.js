import {
  AeadId,
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  // DhkemP256HkdfSha256,
  // DhkemP384HkdfSha384,
  // DhkemP521HkdfSha512,
  ExportOnly,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
  KdfId,
} from "./hpke-core.js";

import { DhkemSecp256k1HkdfSha256 } from "./hpke-dhkem-secp256k1.js";

// function createKem(id) {
//   switch (id) {
//     case KemId.DhkemP256HkdfSha256:
//       return new DhkemP256HkdfSha256();
//     case KemId.DhkemP384HkdfSha384:
//       return new DhkemP384HkdfSha384();
//     case KemId.DhkemP521HkdfSha512:
//       return new DhkemP521HkdfSha512();
//     default:
//       break;
//   }
//   throw new Error("ng: invalid kem");
// }

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

function createAead(id) {
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

export async function testServer(request) {
  const url = new URL(request.url);
  if (url.pathname !== "/test") {
    return new Response("ng: invalid path");
  }
  const params = url.searchParams;
  const kdfStr = params.get("kdf");
  const aeadStr = params.get("aead");
  if (kdfStr === null || aeadStr === null) {
    return new Response("ng: invalid params");
  }
  const kem = new DhkemSecp256k1HkdfSha256();
  const kdf = Number.parseInt(kdfStr);
  const aead = Number.parseInt(aeadStr);
  if (Number.isNaN(kdf) || Number.isNaN(aead)) {
    return new Response("ng: invalid params");
  }

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
    if ("hello world!" !== new TextDecoder().decode(pt)) {
      return new Response("ng");
    }
  } catch (e) {
    return new Response("ng: " + e.message);
  }
  return new Response("ok");
}
