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
} from "@hpke/core";

import { DhkemSecp256k1HkdfSha256 } from "@hpke/dhkem-secp256k1";

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
    case AeadId.ExportOnly:
      return new ExportOnly();
    default:
      break;
  }
  throw new Error("ng: invalid aead");
}

function parseRuntimeId<T extends number>(
  value: string,
  name: string,
): T {
  const parsed = Number.parseInt(value);
  if (Number.isNaN(parsed)) {
    throw new Error(`ng: invalid ${name}`);
  }
  return parsed as T;
}

export async function testServer(request: Request): Promise<Response> {
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
  let kdfId: KdfId;
  let aeadId: AeadId;
  try {
    kdfId = parseRuntimeId<KdfId>(kdfStr, "kdf");
    aeadId = parseRuntimeId<AeadId>(aeadStr, "aead");
  } catch {
    return new Response("ng: invalid params");
  }
  try {
    const suite = new CipherSuite({
      kem: new DhkemSecp256k1HkdfSha256(),
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
