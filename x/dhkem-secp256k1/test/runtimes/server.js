import * as hpke from "./hpke.js";
import * as secp256k1 from "./hpke-dhkem-secp256k1.js";

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
  const kem = new secp256k1.DhkemSecp256k1HkdfSha256();
  const kdf = Number.parseInt(kdfStr);
  const aead = Number.parseInt(aeadStr);
  if (Number.isNaN(kdf) || Number.isNaN(aead)) {
    return new Response("ng: invalid params");
  }

  try {
    const suite = new hpke.CipherSuite({ kem: kem, kdf: kdf, aead: aead });
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
  } catch (e) {
    return new Response("ng: " + e.message);
  }
  return new Response("ok");
}
