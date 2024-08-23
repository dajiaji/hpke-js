import { CipherSuite } from "@hpke/hpke-js";

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
  if (Number.isNaN(kem) || Number.isNaN(kdf) || Number.isNaN(aead)) {
    return new Response("ng: invalid params");
  }

  try {
    const suite = new CipherSuite({ kem: kem, kdf: kdf, aead: aead });
    const rkp = await suite.generateKeyPair();
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
