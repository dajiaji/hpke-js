import { expect, test } from "bun:test";

import {
  Aes128Gcm,
  createHpke0,
  createHpke0Ke,
  createHpke3,
  createHpke3Ke,
} from "@hpke/cose";

test("bun - Encrypt0 with HPKE-0 (P-256, AES-128-GCM)", async () => {
  const e0 = createHpke0();
  const kp = await e0.suite.kem.generateKeyPair();
  const ct = await e0.seal(
    kp.publicKey,
    new TextEncoder().encode("hello world!"),
  );
  const pt = await e0.open(kp, ct);
  expect(new TextDecoder().decode(pt)).toBe("hello world!");
});

test("bun - Encrypt0 with HPKE-3 (X25519, AES-128-GCM)", async () => {
  const e0 = createHpke3();
  const kp = await e0.suite.kem.generateKeyPair();
  const ct = await e0.seal(
    kp.publicKey,
    new TextEncoder().encode("hello world!"),
  );
  const pt = await e0.open(kp, ct);
  expect(new TextDecoder().decode(pt)).toBe("hello world!");
});

test("bun - KE with HPKE-0-KE (P-256, A128GCM content)", async () => {
  const ke = createHpke0Ke(new Aes128Gcm());
  const kp = await ke.generateKemKeyPair();
  const ct = await ke.seal(
    [{ recipientPublicKey: kp.publicKey }],
    new TextEncoder().encode("hello world!"),
  );
  const pt = await ke.open(kp, ct);
  expect(new TextDecoder().decode(pt)).toBe("hello world!");
});

test("bun - KE with HPKE-3-KE (X25519, A128GCM content)", async () => {
  const ke = createHpke3Ke(new Aes128Gcm());
  const kp = await ke.generateKemKeyPair();
  const ct = await ke.seal(
    [{ recipientPublicKey: kp.publicKey }],
    new TextEncoder().encode("hello world!"),
  );
  const pt = await ke.open(kp, ct);
  expect(new TextDecoder().decode(pt)).toBe("hello world!");
});

// The following tests run only the CBOR decoder: open() decodes the message
// before using the key.
async function openError(data: Uint8Array): Promise<string> {
  try {
    await createHpke0().open({} as CryptoKey, data);
  } catch (e: unknown) {
    return (e as Error).message;
  }
  return "";
}

test("bun - CBOR decoder with valid text string", async () => {
  // "\u00fc" is decoded and then rejected as not being a COSE_Encrypt0.
  expect(await openError(new Uint8Array([0x62, 0xc3, 0xbc]))).toBe(
    "Invalid COSE_Encrypt0 structure",
  );
});

test("bun - CBOR decoder with invalid UTF-8 in a text string", async () => {
  expect(await openError(new Uint8Array([0x62, 0xc3, 0x28]))).toBe(
    "CBOR: invalid UTF-8 in text string",
  );
});

test("bun - CBOR decoder with leading BOM in a text string", async () => {
  // {"\ufeffa": 1, "a": 2} has duplicate keys if the BOM is dropped.
  expect(
    await openError(
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
    ),
  ).toBe("Invalid COSE_Encrypt0 structure");
});
