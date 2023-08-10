import * as hpke from "./hpke-core.js";
import { Chacha20Poly1305 } from "./hpke-chacha20poly1305.js";

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
    const suite = new hpke.CipherSuite({ kem: kem, kdf: kdf, aead: aead });
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
