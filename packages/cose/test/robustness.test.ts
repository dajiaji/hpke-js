import { assertEquals, assertInstanceOf, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  type AeadInterface,
  Aes128Gcm,
  buildEc2CoseKey,
  CoseCrv,
  CoseError,
  createHpke0,
  createHpke3,
  createHpke3Ke,
} from "../mod.ts";
import { encode } from "../src/cbor/encoder.ts";
import { decode } from "../src/cbor/decoder.ts";
import type { CborValue } from "../src/cbor/types.ts";

const PLAINTEXT = new TextEncoder().encode("robustness");
const KID = 4;

function hex(s: string): Uint8Array {
  return new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));
}

/**
 * An AES-128-GCM AEAD that records the key buffers it is given.
 * With failSeal, every seal() rejects after the key has been recorded.
 */
function recordingAead(
  { failSeal = false } = {},
): { aead: AeadInterface; keys: Uint8Array[] } {
  const inner = new Aes128Gcm();
  const keys: Uint8Array[] = [];
  const aead: AeadInterface = {
    id: inner.id,
    keySize: inner.keySize,
    nonceSize: inner.nonceSize,
    tagSize: inner.tagSize,
    createEncryptionContext(key) {
      keys.push(key as Uint8Array);
      const ctx = inner.createEncryptionContext(key);
      if (!failSeal) {
        return ctx;
      }
      return {
        seal: () => Promise.reject(new Error("injected seal failure")),
        open: (iv, data, aad) => ctx.open(iv, data, aad),
      };
    },
  };
  return { aead, keys };
}

async function sealEncrypt() {
  const enc = createHpke3Ke(new Aes128Gcm());
  const rkp = await enc.generateKemKeyPair();
  const ct = await enc.seal([{ recipientPublicKey: rkp.publicKey }], PLAINTEXT);
  return { enc, rkp, msg: decode(ct) as CborValue[] };
}

describe("Errors are reported as CoseError", () => {
  it("CBOR decoding errors", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();
    await assertRejects(
      () => enc0.open(rkp, new Uint8Array([0x83])),
      CoseError,
      "CBOR: unexpected end of input",
    );
  });

  it("Encrypt0: HPKE decryption failure keeps the cause", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();
    const other = await enc0.suite.kem.generateKeyPair();
    const ct = await enc0.seal(rkp.publicKey, PLAINTEXT);
    const err = await assertRejects(
      () => enc0.open(other, ct),
      CoseError,
      "Decryption failed",
    );
    assertInstanceOf(err.cause, Error);
  });

  it("Encrypt0: HPKE encryption failure", async () => {
    // An X25519 key cannot be used with the P-256 suite.
    const x25519 = await createHpke3().suite.kem.generateKeyPair();
    await assertRejects(
      () => createHpke0().seal(x25519.publicKey, PLAINTEXT),
      CoseError,
      "Encryption failed",
    );
  });

  it("Encrypt: content decryption failure", async () => {
    const { enc, rkp, msg } = await sealEncrypt();
    const ciphertext = msg[2] as Uint8Array;
    ciphertext[0] ^= 0x01;
    await assertRejects(
      () => enc.open(rkp, encode(msg)),
      CoseError,
      "Content decryption failed",
    );
  });

  it("COSE_Key import failure keeps the cause", async () => {
    // A well-formed P-384 COSE_Key cannot be imported into the P-256 suite.
    const coord = new Uint8Array(48);
    const coseKey = buildEc2CoseKey(CoseCrv.P384, coord, coord);
    const err = await assertRejects(
      () => createHpke0().importPublicCoseKey(coseKey),
      CoseError,
      "Failed to import COSE_Key",
    );
    assertInstanceOf(err.cause, Error);
  });
});

describe("CEK zeroization", () => {
  it("clears the CEK after seal and open", async () => {
    const { aead, keys } = recordingAead();
    const enc = createHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();

    const ct = await enc.seal(
      [{ recipientPublicKey: rkp.publicKey }],
      PLAINTEXT,
    );
    assertEquals(await enc.open(rkp, ct), PLAINTEXT);

    assertEquals(keys.length, 2);
    for (const key of keys) {
      assertEquals(key, new Uint8Array(key.length));
    }
  });

  it("clears the CEK when content decryption fails", async () => {
    const { aead, keys } = recordingAead();
    const enc = createHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();
    const msg = decode(
      await enc.seal([{ recipientPublicKey: rkp.publicKey }], PLAINTEXT),
    ) as CborValue[];
    (msg[2] as Uint8Array)[0] ^= 0x01;

    await assertRejects(() => enc.open(rkp, encode(msg)), CoseError);
    assertEquals(keys[1], new Uint8Array(keys[1].length));
  });

  it("clears the CEK when content encryption fails during seal", async () => {
    const { aead, keys } = recordingAead({ failSeal: true });
    const enc = createHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();

    await assertRejects(
      () => enc.seal([{ recipientPublicKey: rkp.publicKey }], PLAINTEXT),
      CoseError,
      "Encryption failed",
    );
    assertEquals(keys.length, 1);
    assertEquals(keys[0], new Uint8Array(keys[0].length));
  });

  it("clears the CEK when wrapping it for a recipient fails", async () => {
    const { aead, keys } = recordingAead();
    const enc = createHpke3Ke(aead);
    const rkp = await enc.generateKemKeyPair();
    // A P-256 key cannot be used with the X25519 suite of HPKE-3-KE.
    const p256 = await createHpke0().suite.kem.generateKeyPair();

    await assertRejects(
      () =>
        enc.seal(
          [
            { recipientPublicKey: rkp.publicKey },
            { recipientPublicKey: p256.publicKey },
          ],
          PLAINTEXT,
        ),
      CoseError,
      "Encryption failed",
    );
    assertEquals(keys.length, 1);
    assertEquals(keys[0], new Uint8Array(keys[0].length));
  });
});

describe("CBOR decoder bounds checks", () => {
  const cases: [string, string][] = [
    ["uint8 argument missing", "18"],
    ["uint16 argument truncated", "1901"],
    ["uint32 argument truncated", "1a000001"],
    ["uint64 argument truncated", "1b00000000000001"],
    ["byte string longer than input", "5a7fffffff00"],
    ["array longer than input", "9a7fffffff00"],
    ["map longer than input", "ba7fffffff0000"],
  ];
  for (const [name, encoded] of cases) {
    it(`reports a truncated ${name} as unexpected end of input`, async () => {
      const enc0 = createHpke3();
      const rkp = await enc0.suite.kem.generateKeyPair();
      await assertRejects(
        () => enc0.open(rkp, hex(encoded)),
        CoseError,
        "CBOR: unexpected end of input",
      );
    });
  }
});

describe("Recipient kid matching", () => {
  it("matches a kid in the recipient unprotected header", async () => {
    const enc = createHpke3Ke(new Aes128Gcm());
    const rkpA = await enc.generateKemKeyPair();
    const rkpB = await enc.generateKemKeyPair();
    const msg = decode(
      await enc.seal(
        [
          { recipientPublicKey: rkpA.publicKey },
          { recipientPublicKey: rkpB.publicKey },
        ],
        PLAINTEXT,
      ),
    ) as CborValue[];
    const recipients = msg[3] as CborValue[][];
    (recipients[0][1] as Map<CborValue, CborValue>).set(KID, hex("aa"));
    (recipients[1][1] as Map<CborValue, CborValue>).set(KID, hex("bb"));
    const data = encode(msg);

    assertEquals(await enc.open(rkpB, data, { kid: hex("bb") }), PLAINTEXT);
    await assertRejects(
      () => enc.open(rkpB, data, { kid: hex("cc") }),
      CoseError,
      "No matching recipient found or decryption failed",
    );
  });
});

describe("Header labels in both protected and unprotected buckets", () => {
  it("Encrypt0: rejects a duplicated label", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();
    const msg = decode(
      await enc0.seal(rkp.publicKey, PLAINTEXT),
    ) as CborValue[];
    (msg[1] as Map<CborValue, CborValue>).set(1, 41); // alg
    await assertRejects(
      () => enc0.open(rkp, encode(msg)),
      CoseError,
      "Header label 1 appears in both protected and unprotected headers",
    );
  });

  it("Encrypt: rejects a duplicated label in Layer 0", async () => {
    const { enc, rkp, msg } = await sealEncrypt();
    (msg[1] as Map<CborValue, CborValue>).set(1, 1); // alg
    await assertRejects(
      () => enc.open(rkp, encode(msg)),
      CoseError,
      "Header label 1 appears in both protected and unprotected headers",
    );
  });

  it("Encrypt: skips a recipient with a duplicated label", async () => {
    const enc = createHpke3Ke(new Aes128Gcm());
    const rkp = await enc.generateKemKeyPair();
    const msg = decode(
      await enc.seal(
        [{ recipientPublicKey: rkp.publicKey, kid: hex("aa") }],
        PLAINTEXT,
      ),
    ) as CborValue[];
    const recipient = (msg[3] as CborValue[][])[0];
    (recipient[1] as Map<CborValue, CborValue>).set(KID, hex("aa"));
    await assertRejects(
      () => enc.open(rkp, encode(msg)),
      CoseError,
      "No matching recipient found or decryption failed",
    );
  });
});
