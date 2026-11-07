import { assertEquals, assertRejects, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  DecapError,
  Dhkem,
  type DhkemPrimitives,
  EncapError,
  HkdfSha256Native,
  KemId,
  XCryptoKey,
} from "../mod.ts";

type Failure = "dh1" | "dh2" | "context" | "ikm" | "info" | "derive";

function fixture(auth: boolean, failure?: Failure) {
  const privateKey = new XCryptoKey("test", new Uint8Array([7]), "private");
  const publicKey = new XCryptoKey("test", new Uint8Array([8]), "public");
  const pair = { privateKey, publicKey };
  const rawDh: Uint8Array[] = [];
  const retained: Uint8Array[] = [];
  const result = new Uint8Array(32).fill(9);
  let publicExports = 0;
  let deriving = false;
  let release: () => void = () => {};
  const pending = new Promise<void>((resolve) => release = resolve);
  const fail = (stage: Failure) => {
    if (failure === stage) throw new Error(`failed ${stage}`);
  };

  const prim: DhkemPrimitives = {
    generateKeyPair: () => Promise.resolve(pair),
    deriveKeyPair: () => Promise.resolve(pair),
    derivePublicKey: () => Promise.resolve(publicKey),
    importKey: () => Promise.resolve(publicKey),
    serializePrivateKey: () => Promise.resolve(new Uint8Array([7]).buffer),
    deserializePrivateKey: () => Promise.resolve(privateKey),
    deserializePublicKey: () => Promise.resolve(publicKey),
    serializePublicKey: () => {
      publicExports++;
      // encap exports enc and pkR before DH; decap only exports pkR.
      // Subsequent exports construct the authenticated KEM context.
      if (auth && rawDh.length === 2) fail("context");
      return Promise.resolve(new Uint8Array([publicExports]).buffer);
    },
    dh: () => {
      fail(rawDh.length === 0 ? "dh1" : "dh2");
      const bytes = new Uint8Array(32).fill(rawDh.length + 1);
      rawDh.push(bytes);
      return Promise.resolve(bytes.buffer);
    },
  };

  class ObservedKdf extends HkdfSha256Native {
    override buildLabeledIkm(label: Uint8Array, ikm: Uint8Array): Uint8Array {
      retained.push(ikm);
      assertEquals(
        ikm,
        auth
          ? new Uint8Array([
            ...new Uint8Array(32).fill(1),
            ...new Uint8Array(32).fill(2),
          ])
          : new Uint8Array(32).fill(1),
      );
      fail("ikm");
      const labeled = super.buildLabeledIkm(label, ikm);
      retained.push(labeled);
      return labeled;
    }

    override buildLabeledInfo(
      label: Uint8Array,
      info: Uint8Array,
      len: number,
    ): Uint8Array {
      fail("info");
      return super.buildLabeledInfo(label, info, len);
    }

    override async extractAndExpand(
      _salt: ArrayBufferLike | ArrayBufferView,
      ikm: ArrayBufferLike | ArrayBufferView,
      _info: ArrayBufferLike | ArrayBufferView,
      _len: number,
    ): Promise<ArrayBuffer> {
      deriving = true;
      await pending;
      // The caller must await completion before clearing either KDF input.
      assertEquals(new Uint8Array(retained[0]).some((b) => b !== 0), true);
      assertStrictEquals(ikm, retained[1]);
      assertEquals(retained[1].some((b) => b !== 0), true);
      fail("derive");
      return result.buffer;
    }
  }

  const kem = new Dhkem(KemId.DhkemX25519HkdfSha256, prim, new ObservedKdf());
  return {
    rawDh,
    retained,
    privateKey,
    publicKey,
    result,
    pending: () => deriving,
    release,
    encap: () =>
      kem.encap({
        recipientPublicKey: publicKey,
        senderKey: auth ? privateKey : undefined,
      }).then((r) => r.sharedSecret),
    decap: () =>
      kem.decap({
        enc: new Uint8Array([3]).buffer,
        recipientKey: pair,
        senderPublicKey: auth ? publicKey : undefined,
      }),
  };
}

describe("DHKEM temporary secret zeroization", () => {
  for (const operation of ["encap", "decap"] as const) {
    for (const auth of [false, true]) {
      const failures: (Failure | undefined)[] = [
        undefined,
        "dh1",
        "ikm",
        "info",
        "derive",
      ];
      if (auth) failures.push("dh2", "context");
      for (const failure of failures) {
        it(`${operation} ${auth ? "Auth" : "Base"} clears secrets on ${failure ?? "success"}`, async () => {
          const f = fixture(auth, failure);
          const work = f[operation]();
          // Attach the rejection handler before yielding to pending operations.
          const checked = failure
            ? assertRejects(
              () => work,
              operation === "encap" ? EncapError : DecapError,
              `failed ${failure}`,
            )
            : work.then((secret) =>
              assertEquals(new Uint8Array(secret), f.result)
            );
          // Let the fake DH and public-key operations reach the KDF.
          for (let i = 0; i < 30 && !f.pending(); i++) await Promise.resolve();
          try {
            if (failure === undefined || failure === "derive") {
              assertEquals(f.pending(), true, "KDF must be awaiting release");
            }
            if (f.pending()) {
              assertEquals(
                f.retained.every((bytes) => bytes.some((b) => b !== 0)),
                true,
              );
              if (auth) {
                assertEquals(
                  f.rawDh.every((bytes) => bytes.every((b) => b === 0)),
                  true,
                );
              }
            }
          } finally {
            f.release();
            await checked;
          }
          for (const bytes of [...f.rawDh, ...f.retained]) {
            assertEquals(bytes, new Uint8Array(bytes.length));
          }
          assertEquals(f.result, new Uint8Array(32).fill(9));
          assertEquals(f.privateKey.key, new Uint8Array([7]));
          assertEquals(f.publicKey.key, new Uint8Array([8]));
        });
      }
    }
  }
});
