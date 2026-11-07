import { assertEquals, assertRejects } from "@std/assert";
import { it } from "@std/testing/bdd";
import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
  NotSupportedError,
} from "../mod.ts";

it("rejects unsupported Auth and AuthPSK before calling the KEM", async () => {
  class UnauthenticatedKem extends DhkemP256HkdfSha256 {
    override encap(): never {
      throw new Error("encap must not be called");
    }
    override decap(): never {
      throw new Error("decap must not be called");
    }
  }
  const kem = new UnauthenticatedKem();
  Object.defineProperty(kem, "auth", { value: false });
  const suite = new CipherSuite({
    kem,
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  const keys = await suite.kem.generateKeyPair();
  for (
    const psk of [undefined, {
      key: new Uint8Array(32),
      id: new Uint8Array([1]),
    }]
  ) {
    await assertRejects(
      () =>
        suite.createSenderContext({
          recipientPublicKey: keys.publicKey,
          senderKey: keys,
          psk,
        }),
      NotSupportedError,
    );
    await assertRejects(
      () =>
        suite.createRecipientContext({
          recipientKey: keys,
          senderPublicKey: keys.publicKey,
          enc: new Uint8Array(),
          psk,
        }),
      NotSupportedError,
    );
  }
});

it("preserves Auth and AuthPSK for legacy KEMs without an auth flag", async () => {
  const kem = new DhkemP256HkdfSha256();
  assertEquals("auth" in kem, false);
  const suite = new CipherSuite({
    kem,
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  const recipient = await kem.generateKeyPair();
  const sender = await kem.generateKeyPair();
  const other = await kem.generateKeyPair();
  const plaintext = new Uint8Array([1, 2, 3]).buffer;
  for (
    const psk of [undefined, {
      key: new Uint8Array(32),
      id: new Uint8Array([1]),
    }]
  ) {
    const sealed = await suite.seal({
      recipientPublicKey: recipient.publicKey,
      senderKey: sender,
      psk,
    }, plaintext);
    const params = {
      recipientKey: recipient,
      enc: sealed.enc,
      senderPublicKey: sender.publicKey,
      psk,
    };
    assertEquals(await suite.open(params, sealed.ct), plaintext);
    await assertRejects(() =>
      suite.open({ ...params, senderPublicKey: other.publicKey }, sealed.ct)
    );
  }
});
