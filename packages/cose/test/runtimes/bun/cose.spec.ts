import { expect, test } from "bun:test";

import {
  ContentAlg,
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
  const ke = createHpke0Ke(ContentAlg.A128GCM);
  const kp = await ke.generateKemKeyPair();
  const ct = await ke.seal(
    [{ recipientPublicKey: kp.publicKey }],
    new TextEncoder().encode("hello world!"),
  );
  const pt = await ke.open(kp, ct);
  expect(new TextDecoder().decode(pt)).toBe("hello world!");
});

test("bun - KE with HPKE-3-KE (X25519, A128GCM content)", async () => {
  const ke = createHpke3Ke(ContentAlg.A128GCM);
  const kp = await ke.generateKemKeyPair();
  const ct = await ke.seal(
    [{ recipientPublicKey: kp.publicKey }],
    new TextEncoder().encode("hello world!"),
  );
  const pt = await ke.open(kp, ct);
  expect(new TextDecoder().decode(pt)).toBe("hello world!");
});
