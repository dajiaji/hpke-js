import {
  ContentAlg,
  createHpke0,
  createHpke0Ke,
  createHpke3,
  createHpke3Ke,
} from "@hpke/cose";

// Runs only the CBOR decoder: open() decodes the message before using the key,
// so this also works on runtimes without the required WebCrypto algorithms.
async function testOpenError(
  data: Uint8Array,
  expected: string,
): Promise<Response> {
  try {
    await createHpke0().open({} as CryptoKey, data);
  } catch (e: unknown) {
    const message = (e as Error).message;
    return new Response(message === expected ? "ok" : "ng: " + message);
  }
  return new Response("ng: open() should fail");
}

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
      case "encrypt0-hpke0": {
        const e0 = createHpke0();
        const kp = await e0.suite.kem.generateKeyPair();
        const ct = await e0.seal(kp.publicKey, msg);
        const pt = await e0.open(kp, ct);
        if ("hello world!" !== new TextDecoder().decode(pt)) {
          return new Response("ng");
        }
        break;
      }
      case "encrypt0-hpke3": {
        const e0 = createHpke3();
        const kp = await e0.suite.kem.generateKeyPair();
        const ct = await e0.seal(kp.publicKey, msg);
        const pt = await e0.open(kp, ct);
        if ("hello world!" !== new TextDecoder().decode(pt)) {
          return new Response("ng");
        }
        break;
      }
      case "ke-hpke0": {
        const ke = createHpke0Ke(ContentAlg.A128GCM);
        const kp = await ke.generateKemKeyPair();
        const ct = await ke.seal(
          [{ recipientPublicKey: kp.publicKey }],
          msg,
        );
        const pt = await ke.open(kp, ct);
        if ("hello world!" !== new TextDecoder().decode(pt)) {
          return new Response("ng");
        }
        break;
      }
      case "ke-hpke3": {
        const ke = createHpke3Ke(ContentAlg.A128GCM);
        const kp = await ke.generateKemKeyPair();
        const ct = await ke.seal(
          [{ recipientPublicKey: kp.publicKey }],
          msg,
        );
        const pt = await ke.open(kp, ct);
        if ("hello world!" !== new TextDecoder().decode(pt)) {
          return new Response("ng");
        }
        break;
      }
      case "text-valid":
        // "\u00fc" is decoded and then rejected as not being a COSE_Encrypt0.
        return await testOpenError(
          new Uint8Array([0x62, 0xc3, 0xbc]),
          "Invalid COSE_Encrypt0 structure",
        );
      case "text-invalid-utf8":
        return await testOpenError(
          new Uint8Array([0x62, 0xc3, 0x28]),
          "CBOR: invalid UTF-8 in text string",
        );
      case "text-bom":
        // {"\ufeffa": 1, "a": 2} has duplicate keys if the BOM is dropped.
        return await testOpenError(
          new Uint8Array([
            0xa2,
            0x64,
            0xef,
            0xbb,
            0xbf,
            0x61,
            0x01,
            0x61,
            0x61,
            0x02,
          ]),
          "Invalid COSE_Encrypt0 structure",
        );
      default:
        return new Response("ng: unknown case");
    }
  } catch (e: unknown) {
    return new Response("ng: " + (e as Error).message);
  }
  return new Response("ok");
}
