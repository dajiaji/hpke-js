import {
  AeadId,
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  ExportOnly,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
  KdfId,
  KemId,
} from "@hpke/core";

function createKem(id: KemId) {
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

function createKdf(id: KdfId) {
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

function createAead(id: AeadId) {
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
  const kemId = Number.parseInt(kemStr);
  const kdfId = Number.parseInt(kdfStr);
  const aeadId = Number.parseInt(aeadStr);
  if (Number.isNaN(kemId) || Number.isNaN(kdfId) || Number.isNaN(aeadId)) {
    return new Response("ng: invalid params");
  }
  try {
    const suite = new CipherSuite({
      kem: createKem(kemId),
      kdf: createKdf(kdfId),
      aead: createAead(aeadId),
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
