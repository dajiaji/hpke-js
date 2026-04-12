import {
  ContentEncAlg,
  createHpke0,
  createHpke0Ke,
  createHpke3,
  createHpke3Ke,
} from "@hpke/jose";

export async function testServer(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== "/test") {
    return new Response("ng: invalid path");
  }
  const testCase = url.searchParams.get("case");
  if (testCase === null) {
    return new Response("ng: invalid params");
  }
  const msg = new TextEncoder().encode("hello world!");

  try {
    switch (testCase) {
      case "integrated-hpke0": {
        const e0 = createHpke0();
        const kp = await e0.suite.kem.generateKeyPair();
        const jwe = await e0.seal(kp.publicKey, msg);
        const pt = await e0.open(kp, jwe);
        if ("hello world!" !== new TextDecoder().decode(pt)) {
          return new Response("ng");
        }
        break;
      }
      case "integrated-hpke3": {
        const e0 = createHpke3();
        const kp = await e0.suite.kem.generateKeyPair();
        const jwe = await e0.seal(kp.publicKey, msg);
        const pt = await e0.open(kp, jwe);
        if ("hello world!" !== new TextDecoder().decode(pt)) {
          return new Response("ng");
        }
        break;
      }
      case "ke-hpke0": {
        const ke = createHpke0Ke(ContentEncAlg.A128GCM);
        const kp = await ke.generateKemKeyPair();
        const jwe = await ke.seal(
          [{ recipientPublicKey: kp.publicKey }],
          msg,
        );
        const pt = await ke.open(kp, jwe);
        if ("hello world!" !== new TextDecoder().decode(pt)) {
          return new Response("ng");
        }
        break;
      }
      case "ke-hpke3": {
        const ke = createHpke3Ke(ContentEncAlg.A128GCM);
        const kp = await ke.generateKemKeyPair();
        const jwe = await ke.seal(
          [{ recipientPublicKey: kp.publicKey }],
          msg,
        );
        const pt = await ke.open(kp, jwe);
        if ("hello world!" !== new TextDecoder().decode(pt)) {
          return new Response("ng");
        }
        break;
      }
      default:
        return new Response("ng: unknown case");
    }
  } catch (e: unknown) {
    return new Response("ng: " + (e as Error).message);
  }
  return new Response("ok");
}
