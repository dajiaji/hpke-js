import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  DeserializeError,
  hexToBytes,
  HkdfSha256Native,
  HkdfSha512Native,
  type KdfInterface,
  loadSubtleCrypto,
  SerializeError,
  X_CURVE_X25519,
  X_CURVE_X448,
  type XCurve,
  XCurveNativeDhkemPrimitives,
} from "../mod.ts";

// DOMException is not a global on Node.js 16.
function webCryptoError(name: string): Error {
  const e = new Error(name);
  e.name = name;
  return e;
}

// Simulates WebKit, which rejects a PKCS#8 X25519 private key whose first
// byte is 0x00 and fails to generate such a key pair (about 1 in 256 times).
async function emulateWebKit(
  x: XCurveNativeDhkemPrimitives,
  algIdLength: number,
  opts: { failGenerateKey: boolean },
): Promise<void> {
  const holder = x as unknown as { _api: SubtleCrypto };
  const api = await loadSubtleCrypto();
  holder._api = new Proxy(api, {
    get(obj, prop) {
      if (prop === "importKey") {
        return (format: KeyFormat, keyData: unknown, ...rest: unknown[]) => {
          if (
            format === "pkcs8" &&
            new Uint8Array(keyData as ArrayBuffer)[algIdLength] === 0
          ) {
            return Promise.reject(webCryptoError("DataError"));
          }
          // deno-lint-ignore no-explicit-any
          return (obj.importKey as any)(format, keyData, ...rest);
        };
      }
      if (prop === "generateKey" && opts.failGenerateKey) {
        return () => Promise.reject(webCryptoError("OperationError"));
      }
      const v = Reflect.get(obj, prop);
      return typeof v === "function" ? v.bind(obj) : v;
    },
  });
}

// suite_id = concat("KEM", I2OSP(kem_id, 2))
function kemKdf(kdf: KdfInterface, kemId: number): () => KdfInterface {
  return () => {
    kdf.init(new Uint8Array([75, 69, 77, kemId >> 8, kemId & 0xff]));
    return kdf;
  };
}

const CURVES: [XCurve, () => KdfInterface][] = [
  [X_CURVE_X25519, kemKdf(new HkdfSha256Native(), 0x0020)],
  [X_CURVE_X448, kemKdf(new HkdfSha512Native(), 0x0021)],
];

describe("XCurveNativeDhkemPrimitives", () => {
  it("X25519 deriveKeyPair should match RFC 9180 A.1.1 (skEm/pkEm)", async () => {
    const x = new XCurveNativeDhkemPrimitives(X_CURVE_X25519, CURVES[0][1]());
    const kp = await x.deriveKeyPair(
      hexToBytes(
        "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
      ),
    );
    assertEquals(
      new Uint8Array(await x.serializePrivateKey(kp.privateKey)),
      hexToBytes(
        "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
      ),
    );
    assertEquals(
      new Uint8Array(await x.serializePublicKey(kp.publicKey)),
      hexToBytes(
        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
      ),
    );
  });

  for (const [curve, kdf] of CURVES) {
    describe(curve.name, () => {
      it("deriveKeyPair should be deterministic and yield a valid key pair", async () => {
        const x = new XCurveNativeDhkemPrimitives(curve, kdf());
        const ikm = new Uint8Array(32).fill(1);
        const kp1 = await x.deriveKeyPair(ikm);
        const kp2 = await x.deriveKeyPair(ikm);
        const sk1 = new Uint8Array(await x.serializePrivateKey(kp1.privateKey));
        const sk2 = new Uint8Array(await x.serializePrivateKey(kp2.privateKey));
        assertEquals(sk1.length, curve.size);
        assertEquals(sk1, sk2);
        const pk = new Uint8Array(await x.serializePublicKey(kp1.publicKey));
        assertEquals(pk.length, curve.size);
        assertEquals(
          pk,
          new Uint8Array(
            await x.serializePublicKey(await x.derivePublicKey(kp1.privateKey)),
          ),
        );
      });

      it("dh should agree for both parties", async () => {
        const x = new XCurveNativeDhkemPrimitives(curve, kdf());
        const a = await x.generateKeyPair();
        const b = await x.generateKeyPair();
        const ab = new Uint8Array(await x.dh(a.privateKey, b.publicKey));
        assertEquals(ab.length, curve.size);
        assertEquals(
          ab,
          new Uint8Array(await x.dh(b.privateKey, a.publicKey)),
        );
      });

      it("should round-trip raw private and public keys", async () => {
        const x = new XCurveNativeDhkemPrimitives(curve, kdf());
        const kp = await x.generateKeyPair();
        const rawSk = await x.serializePrivateKey(kp.privateKey);
        const rawPk = await x.serializePublicKey(kp.publicKey);
        const sk = await x.deserializePrivateKey(rawSk);
        const pk = await x.deserializePublicKey(rawPk);
        assertEquals(
          new Uint8Array(await x.serializePrivateKey(sk)),
          new Uint8Array(rawSk),
        );
        assertEquals(
          new Uint8Array(await x.serializePublicKey(pk)),
          new Uint8Array(rawPk),
        );
      });

      it("should handle a private key with a leading 0x00 when PKCS#8 import rejects it", async () => {
        const x = new XCurveNativeDhkemPrimitives(curve, kdf());
        // Computed without the emulation as the expected values.
        const raw = new Uint8Array(curve.size).map((_, i) => i);
        const expectedPk = new Uint8Array(
          await x.serializePublicKey(
            await x.derivePublicKey(await x.deserializePrivateKey(raw)),
          ),
        );
        const peer = await x.generateKeyPair();
        const expectedDh = new Uint8Array(
          await x.dh(await x.deserializePrivateKey(raw), peer.publicKey),
        );

        await emulateWebKit(x, curve.pkcs8AlgId.length, {
          failGenerateKey: false,
        });
        const sk = await x.deserializePrivateKey(raw);
        assertEquals(new Uint8Array(await x.serializePrivateKey(sk)), raw);
        assertEquals(
          new Uint8Array(
            await x.serializePublicKey(await x.derivePublicKey(sk)),
          ),
          expectedPk,
        );
        assertEquals(
          new Uint8Array(await x.dh(sk, peer.publicKey)),
          expectedDh,
        );
      });

      it("generateKeyPair should fall back to a random private key when generateKey fails", async () => {
        const x = new XCurveNativeDhkemPrimitives(curve, kdf());
        await emulateWebKit(x, curve.pkcs8AlgId.length, {
          failGenerateKey: true,
        });
        const a = await x.generateKeyPair();
        const b = await x.generateKeyPair();
        assertEquals(
          new Uint8Array(await x.serializePrivateKey(a.privateKey)).length,
          curve.size,
        );
        assertEquals(
          new Uint8Array(await x.dh(a.privateKey, b.publicKey)),
          new Uint8Array(await x.dh(b.privateKey, a.publicKey)),
        );
      });

      it("should reject keys of the wrong length", async () => {
        const x = new XCurveNativeDhkemPrimitives(curve, kdf());
        await assertRejects(
          () => x.deserializePublicKey(new Uint8Array(curve.size - 1)),
          DeserializeError,
        );
        await assertRejects(
          () => x.deserializePrivateKey(new Uint8Array(curve.size + 1)),
          DeserializeError,
        );
      });

      it("dh should reject an all-zero public key", async () => {
        const x = new XCurveNativeDhkemPrimitives(curve, kdf());
        const kp = await x.generateKeyPair();
        const zero = await x.deserializePublicKey(new Uint8Array(curve.size));
        await assertRejects(() => x.dh(kp.privateKey, zero), SerializeError);
      });
    });
  }
});
