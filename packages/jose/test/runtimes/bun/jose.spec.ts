import { expect, test } from "bun:test";

import {
  ContentEncAlg,
  createHpke0,
  createHpke0Ke,
  createHpke3,
  createHpke3Ke,
} from "@hpke/jose";

test("bun - Integrated Encryption with HPKE-0 (P-256, AES-128-GCM)", async () => {
  const e0 = createHpke0();
  const kp = await e0.suite.kem.generateKeyPair();
  const jwe = await e0.seal(
    kp.publicKey,
    new TextEncoder().encode("hello world!"),
  );
  const pt = await e0.open(kp, jwe);
  expect(new TextDecoder().decode(pt)).toBe("hello world!");
});

test("bun - Integrated Encryption with HPKE-3 (X25519, AES-128-GCM)", async () => {
  const e0 = createHpke3();
  const kp = await e0.suite.kem.generateKeyPair();
  const jwe = await e0.seal(
    kp.publicKey,
    new TextEncoder().encode("hello world!"),
  );
  const pt = await e0.open(kp, jwe);
  expect(new TextDecoder().decode(pt)).toBe("hello world!");
});

test("bun - Key Encryption with HPKE-0-KE (P-256, A128GCM content)", async () => {
  const ke = createHpke0Ke(ContentEncAlg.A128GCM);
  const kp = await ke.generateKemKeyPair();
  const jwe = await ke.seal(
    [{ recipientPublicKey: kp.publicKey }],
    new TextEncoder().encode("hello world!"),
  );
  const pt = await ke.open(kp, jwe);
  expect(new TextDecoder().decode(pt)).toBe("hello world!");
});

test("bun - Key Encryption with HPKE-3-KE (X25519, A128GCM content)", async () => {
  const ke = createHpke3Ke(ContentEncAlg.A128GCM);
  const kp = await ke.generateKemKeyPair();
  const jwe = await ke.seal(
    [{ recipientPublicKey: kp.publicKey }],
    new TextEncoder().encode("hello world!"),
  );
  const pt = await ke.open(kp, jwe);
  expect(new TextDecoder().decode(pt)).toBe("hello world!");
});
