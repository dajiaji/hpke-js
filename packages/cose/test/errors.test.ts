import { assertEquals, assertRejects, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  ContentAlg,
  CoseError,
  createHpke3,
  createHpke3Ke,
  createHpke7,
} from "../mod.ts";
import { encode, encodeTagged } from "../src/cbor/encoder.ts";
import { decode } from "../src/cbor/decoder.ts";
import type { CborValue } from "../src/cbor/types.ts";
import {
  buildOkpCoseKey,
  CoseCrv,
  extractPrivateKeyBytes,
  extractPublicKeyBytes,
} from "../src/coseKey.ts";

describe("Malformed CBOR input", () => {
  it("should reject truncated CBOR", () => {
    assertThrows(
      () => decode(new Uint8Array([0x83])), // array of 3 but no items
      Error,
      "unexpected end of input",
    );
  });

  it("should reject CBOR with trailing bytes", () => {
    const valid = encode(42);
    const withTrailing = new Uint8Array(valid.length + 1);
    withTrailing.set(valid);
    withTrailing[valid.length] = 0xff;
    assertThrows(
      () => decode(withTrailing),
      Error,
      "trailing bytes",
    );
  });

  it("should reject unsupported simple values", () => {
    // CBOR simple value true (0xf5)
    assertThrows(
      () => decode(new Uint8Array([0xf5])),
      Error,
      "unsupported simple value",
    );
  });
});

describe("Malformed COSE_Encrypt0 structures", () => {
  it("should reject non-array input", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    // Encode a single integer instead of an array
    const badData = encode(42);
    await assertRejects(
      async () => await enc0.open(rkp, badData),
      CoseError,
      "Invalid COSE_Encrypt0 structure",
    );
  });

  it("should reject array with wrong length", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    // Array with only 2 elements
    const badData = encode(["Encrypt0", new Uint8Array(0)] as CborValue[]);
    await assertRejects(
      async () => await enc0.open(rkp, badData),
      CoseError,
      "Invalid COSE_Encrypt0 structure",
    );
  });

  it("should reject non-bstr protected header", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    // Protected header is a number, not bstr
    const badData = encode([42, new Map(), new Uint8Array(10)] as CborValue[]);
    await assertRejects(
      async () => await enc0.open(rkp, badData),
      CoseError,
      "Invalid protected header",
    );
  });

  it("should reject non-bstr ciphertext", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    const protectedMap = new Map<CborValue, CborValue>();
    protectedMap.set(1, 41); // alg = HPKE-3
    const protectedHeader = encode(protectedMap);

    const badData = encode([protectedHeader, new Map(), 42] as CborValue[]);
    await assertRejects(
      async () => await enc0.open(rkp, badData),
      CoseError,
      "Invalid ciphertext",
    );
  });

  it("should reject algorithm mismatch", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    // Create valid structure but with wrong alg
    const protectedMap = new Map<CborValue, CborValue>();
    protectedMap.set(1, 35); // alg = HPKE-0, but we're using HPKE-3
    const protectedHeader = encode(protectedMap);
    const unprotectedMap = new Map<CborValue, CborValue>();
    unprotectedMap.set(-4, new Uint8Array(32));

    const badData = encode(
      [protectedHeader, unprotectedMap, new Uint8Array(10)] as CborValue[],
    );
    await assertRejects(
      async () => await enc0.open(rkp, badData),
      CoseError,
      "Algorithm mismatch",
    );
  });
});

describe("Malformed COSE_Encrypt structures", () => {
  it("should reject non-array input", async () => {
    const enc = createHpke3Ke(ContentAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();

    const badData = encode("not an array");
    await assertRejects(
      async () => await enc.open(rkp, badData),
      CoseError,
      "Invalid COSE_Encrypt structure",
    );
  });

  it("should reject array with wrong length", async () => {
    const enc = createHpke3Ke(ContentAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();

    // Array with only 3 elements (missing recipients)
    const protectedMap = new Map<CborValue, CborValue>();
    protectedMap.set(1, ContentAlg.A128GCM);
    const ph = encode(protectedMap);
    const badData = encode([ph, new Map(), new Uint8Array(10)] as CborValue[]);
    await assertRejects(
      async () => await enc.open(rkp, badData),
      CoseError,
      "Invalid COSE_Encrypt structure",
    );
  });

  it("should reject content algorithm mismatch", async () => {
    const enc = createHpke3Ke(ContentAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();

    // Use A256GCM in protected header but instance expects A128GCM
    const protectedMap = new Map<CborValue, CborValue>();
    protectedMap.set(1, ContentAlg.A256GCM);
    const ph = encode(protectedMap);
    const unprotectedMap = new Map<CborValue, CborValue>();
    unprotectedMap.set(5, new Uint8Array(12));

    const badData = encode(
      [ph, unprotectedMap, new Uint8Array(10), []] as CborValue[],
    );
    await assertRejects(
      async () => await enc.open(rkp, badData),
      CoseError,
      "Content algorithm mismatch",
    );
  });
});

describe("Cross-algorithm rejection", () => {
  it("Encrypt0: should fail to open with different algorithm instance", async () => {
    const enc3 = createHpke3();
    const enc7 = createHpke7();
    const rkp = await enc3.suite.kem.generateKeyPair();

    const plaintext = new TextEncoder().encode("cross-alg");
    const ct = await enc3.seal(rkp.publicKey, plaintext);

    // Try to open with HPKE-7 (same KEM but different AEAD)
    await assertRejects(
      async () => await enc7.open(rkp, ct),
      CoseError,
      "Algorithm mismatch",
    );
  });

  it("Encrypt: should fail to open with different KE algorithm instance", async () => {
    const enc3 = createHpke3Ke(ContentAlg.A128GCM);
    const rkp = await enc3.generateKemKeyPair();

    const plaintext = new TextEncoder().encode("cross-ke-alg");
    const ct = await enc3.seal(
      [{ recipientPublicKey: rkp.publicKey }],
      plaintext,
    );

    // Open with a different content alg → mismatch at Layer 0
    const enc3b = createHpke3Ke(ContentAlg.A256GCM);
    await assertRejects(
      async () => await enc3b.open(rkp, ct),
      CoseError,
      "Content algorithm mismatch",
    );
  });
});

describe("Tagged COSE structures", () => {
  it("should open tagged COSE_Encrypt0 (tag 16)", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    const plaintext = new TextEncoder().encode("tagged encrypt0");
    const ct = await enc0.seal(rkp.publicKey, plaintext, { tagged: true });

    // Verify it starts with tag
    const decoded = decode(ct);
    // After tag is stripped by decoder, should be an array
    assertEquals(Array.isArray(decoded), true);

    const pt = await enc0.open(rkp, ct);
    assertEquals(pt, plaintext);
  });

  it("should open tagged COSE_Encrypt (tag 96)", async () => {
    const enc = createHpke3Ke(ContentAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();

    const plaintext = new TextEncoder().encode("tagged encrypt");
    const ct = await enc.seal(
      [{ recipientPublicKey: rkp.publicKey }],
      plaintext,
      { tagged: true },
    );

    const pt = await enc.open(rkp, ct);
    assertEquals(pt, plaintext);
  });

  it("should handle externally tagged input", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    // Seal without tag, then manually wrap in tag 16
    const plaintext = new TextEncoder().encode("manual tag");
    const ct = await enc0.seal(rkp.publicKey, plaintext);

    // Manually wrap in tag 16
    const inner = decode(ct);
    const tagged = encodeTagged(16, inner);

    const pt = await enc0.open(rkp, tagged);
    assertEquals(pt, plaintext);
  });
});

describe("Large plaintext", () => {
  it("Encrypt0: should handle 64KB plaintext", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    const plaintext = new Uint8Array(64 * 1024).fill(0xab);
    const ct = await enc0.seal(rkp.publicKey, plaintext);
    const pt = await enc0.open(rkp, ct);

    assertEquals(pt, plaintext);
  });

  it("Encrypt: should handle 64KB plaintext", async () => {
    const enc = createHpke3Ke(ContentAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();

    const plaintext = new Uint8Array(64 * 1024).fill(0xab);
    const ct = await enc.seal(
      [{ recipientPublicKey: rkp.publicKey }],
      plaintext,
    );
    const pt = await enc.open(rkp, ct);

    assertEquals(pt, plaintext);
  });
});

describe("Encrypt0 combined options", () => {
  it("should seal and open with externalAad + info + psk", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    const plaintext = new TextEncoder().encode("all options");
    const opts = {
      externalAad: new Uint8Array([0x01, 0x02]),
      info: new TextEncoder().encode("combined"),
      psk: {
        id: new TextEncoder().encode("psk-combo"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      },
    };
    const ct = await enc0.seal(rkp.publicKey, plaintext, opts);
    const pt = await enc0.open(rkp, ct, opts);

    assertEquals(pt, plaintext);
  });

  it("should seal and open with externalAad + info + psk + kid", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    const plaintext = new TextEncoder().encode("all options + kid");
    const opts = {
      externalAad: new Uint8Array([0x03, 0x04]),
      info: new TextEncoder().encode("full"),
      psk: {
        id: new TextEncoder().encode("psk-full"),
        key: crypto.getRandomValues(new Uint8Array(32)),
      },
      kid: new TextEncoder().encode("my-key"),
    };
    const ct = await enc0.seal(rkp.publicKey, plaintext, opts);
    const pt = await enc0.open(rkp, ct, opts);

    assertEquals(pt, plaintext);
  });
});

describe("Detached payload", () => {
  it("Encrypt0: sealDetached + open with detachedPayload", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    const plaintext = new TextEncoder().encode("detached e0");
    const result = await enc0.sealDetached(rkp.publicKey, plaintext);

    // message has null ciphertext
    const decoded = decode(result.message) as CborValue[];
    assertEquals(decoded[2], null);

    // open with detachedPayload
    const pt = await enc0.open(rkp, result.message, {
      detachedPayload: result.payload,
    });
    assertEquals(pt, plaintext);
  });

  it("Encrypt0: should error on null ciphertext without detachedPayload", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    const plaintext = new TextEncoder().encode("no payload");
    const result = await enc0.sealDetached(rkp.publicKey, plaintext);

    await assertRejects(
      async () => await enc0.open(rkp, result.message),
      CoseError,
      "detached",
    );
  });

  it("Encrypt: sealDetached + open with detachedPayload", async () => {
    const enc = createHpke3Ke(ContentAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();

    const plaintext = new TextEncoder().encode("detached ke");
    const result = await enc.sealDetached(
      [{ recipientPublicKey: rkp.publicKey }],
      plaintext,
    );

    const decoded = decode(result.message) as CborValue[];
    assertEquals(decoded[2], null);

    const pt = await enc.open(rkp, result.message, {
      detachedPayload: result.payload,
    });
    assertEquals(pt, plaintext);
  });
});

describe("alg-omitted interop", () => {
  it("Encrypt0: should decrypt message whose protected header omits alg", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    // Manually build a COSE_Encrypt0 without alg in the protected header,
    // using the same HPKE suite so AAD is consistent.
    const plaintext = new TextEncoder().encode("no alg positive");

    // Protected header: empty map (no alg)
    const protectedMap = new Map<CborValue, CborValue>();
    const protectedHeader = encode(protectedMap);

    // HPKE seal
    const ctx = await enc0.suite.createSenderContext({
      recipientPublicKey: rkp.publicKey,
      info: new Uint8Array(0),
    });
    const encBytes = new Uint8Array(ctx.enc);

    // AAD = Enc_structure("Encrypt0", protectedHeader, empty)
    const aad = encode(
      ["Encrypt0", protectedHeader, new Uint8Array(0)] as CborValue[],
    );
    const ciphertext = new Uint8Array(await ctx.seal(plaintext, aad));

    const unprotectedMap = new Map<CborValue, CborValue>();
    unprotectedMap.set(-4, encBytes); // ek

    const msg = encode(
      [protectedHeader, unprotectedMap, ciphertext] as CborValue[],
    );

    // Should succeed — alg is absent but instance knows the algorithm
    const pt = await enc0.open(rkp, msg);
    assertEquals(pt, plaintext);
  });

  it("Encrypt: should decrypt when Layer 0 protected header omits alg", async () => {
    const enc = createHpke3Ke(ContentAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();

    // Build a normal message first, then rebuild Layer 0 header without alg.
    // To keep the CEK/content correct, seal normally and then strip alg from
    // the Layer 0 protected header and re-encrypt the content with matching AAD.
    const plaintext = new TextEncoder().encode("no alg L0");

    // Generate CEK and nonce
    const cek = crypto.getRandomValues(new Uint8Array(16)); // A128GCM = 16 bytes
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    // Layer 0 protected header: empty (no alg)
    const l0Protected = encode(new Map<CborValue, CborValue>());
    const l0Aad = encode(
      ["Encrypt", l0Protected, new Uint8Array(0)] as CborValue[],
    );

    // AES-GCM content encryption
    const subtle = globalThis.crypto.subtle;
    const aesKey = await subtle.importKey("raw", cek, "AES-GCM", false, [
      "encrypt",
    ]);
    const contentCt = new Uint8Array(
      await subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: l0Aad.buffer as ArrayBuffer,
          tagLength: 128,
        },
        aesKey,
        plaintext,
      ),
    );

    // Wrap CEK for recipient (with alg in recipient header — that's normal)
    const rProtectedMap = new Map<CborValue, CborValue>();
    rProtectedMap.set(1, 49); // alg = HPKE-3-KE
    const rProtected = encode(rProtectedMap);

    // Recipient_structure info
    const recipientInfo = encode([
      "HPKE Recipient",
      1, // next_layer_alg = A128GCM, though Layer 0 header omits it
      rProtected,
      new Uint8Array(0),
    ] as CborValue[]);

    const hpkeCtx = await enc.suite.createSenderContext({
      recipientPublicKey: rkp.publicKey,
      info: recipientInfo,
    });
    const ek = new Uint8Array(hpkeCtx.enc);
    const wrappedCek = new Uint8Array(
      await hpkeCtx.seal(cek, new Uint8Array(0)),
    );

    const rUnprotected = new Map<CborValue, CborValue>();
    rUnprotected.set(-4, ek);

    const l0Unprotected = new Map<CborValue, CborValue>();
    l0Unprotected.set(5, nonce); // IV

    const msg = encode([
      l0Protected,
      l0Unprotected,
      contentCt,
      [[rProtected, rUnprotected, wrappedCek]],
    ] as CborValue[]);

    const pt = await enc.open(rkp, msg);
    assertEquals(pt, plaintext);
  });
});

describe("importCoseKey", () => {
  it("Encrypt0: should import COSE_Key and use for seal/open", async () => {
    const enc0 = createHpke3();
    const rkp = await enc0.suite.kem.generateKeyPair();

    // Export raw key and build COSE_Key
    const rawPub = new Uint8Array(
      await enc0.suite.kem.serializePublicKey(rkp.publicKey),
    );
    const rawPriv = new Uint8Array(
      await enc0.suite.kem.serializePrivateKey(rkp.privateKey),
    );
    const coseKey = buildOkpCoseKey(CoseCrv.X25519, rawPub, rawPriv);

    // Import back via instance method
    const pubKey = await enc0.importPublicCoseKey(coseKey);
    const privKey = await enc0.importPrivateCoseKey(coseKey);

    const plaintext = new TextEncoder().encode("cose key test");
    const ct = await enc0.seal(pubKey, plaintext);
    const pt = await enc0.open(privKey, ct);

    assertEquals(pt, plaintext);
  });

  it("Encrypt: should import COSE_Key and use for seal/open", async () => {
    const enc = createHpke3Ke(ContentAlg.A128GCM);
    const rkp = await enc.generateKemKeyPair();

    const rawPub = new Uint8Array(
      await enc.suite.kem.serializePublicKey(rkp.publicKey),
    );
    const rawPriv = new Uint8Array(
      await enc.suite.kem.serializePrivateKey(rkp.privateKey),
    );
    const coseKey = buildOkpCoseKey(CoseCrv.X25519, rawPub, rawPriv);

    const pubKey = await enc.importPublicCoseKey(coseKey);
    const privKey = await enc.importPrivateCoseKey(coseKey);

    const plaintext = new TextEncoder().encode("cose key ke test");
    const ct = await enc.seal(
      [{ recipientPublicKey: pubKey }],
      plaintext,
    );
    const pt = await enc.open(privKey, ct);

    assertEquals(pt, plaintext);
  });
});

describe("COSE_Key validation", () => {
  it("should reject non-map COSE_Key", () => {
    assertThrows(
      () => extractPublicKeyBytes(encode(42)),
      CoseError,
      "not a CBOR map",
    );
  });

  it("should reject unsupported kty", () => {
    const map = new Map<CborValue, CborValue>();
    map.set(1, 99); // kty = 99 (invalid)
    map.set(-1, CoseCrv.X25519);
    map.set(-2, new Uint8Array(32));
    assertThrows(
      () => extractPublicKeyBytes(encode(map)),
      CoseError,
      "Invalid or unsupported kty",
    );
  });

  it("should reject kty/crv mismatch (OKP key with EC2 curve)", () => {
    const map = new Map<CborValue, CborValue>();
    map.set(1, 1); // kty = OKP
    map.set(-1, CoseCrv.P256); // crv = P-256 (requires kty=EC2)
    map.set(-2, new Uint8Array(32));
    assertThrows(
      () => extractPublicKeyBytes(encode(map)),
      CoseError,
      "kty/crv mismatch",
    );
  });

  it("should reject EC2 key with wrong coordinate length", () => {
    const map = new Map<CborValue, CborValue>();
    map.set(1, 2); // kty = EC2
    map.set(-1, CoseCrv.P256); // crv = P-256 expects 32 bytes
    map.set(-2, new Uint8Array(16)); // x = 16 bytes (wrong)
    map.set(-3, new Uint8Array(32)); // y = 32 bytes
    assertThrows(
      () => extractPublicKeyBytes(encode(map)),
      CoseError,
      "x length 16 does not match",
    );
  });

  it("should reject private key with wrong d length", () => {
    const map = new Map<CborValue, CborValue>();
    map.set(1, 1); // kty = OKP
    map.set(-1, CoseCrv.X25519); // crv = X25519 expects 32 bytes
    map.set(-2, new Uint8Array(32));
    map.set(-4, new Uint8Array(16)); // d = 16 bytes (wrong)
    assertThrows(
      () => extractPrivateKeyBytes(encode(map)),
      CoseError,
      "d length 16 does not match",
    );
  });

  it("should reject private key with invalid key_ops", () => {
    const map = new Map<CborValue, CborValue>();
    map.set(1, 1); // kty = OKP
    map.set(-1, CoseCrv.X25519);
    map.set(-2, new Uint8Array(32));
    map.set(-4, new Uint8Array(32)); // d present = private key
    map.set(4, [1, 2]); // key_ops = [sign, verify] — missing derive bits (8)
    assertThrows(
      () => extractPrivateKeyBytes(encode(map)),
      CoseError,
      "derive bits",
    );
  });

  it("should accept private key with valid key_ops including derive bits", () => {
    const map = new Map<CborValue, CborValue>();
    map.set(1, 1); // kty = OKP
    map.set(-1, CoseCrv.X25519);
    map.set(-2, new Uint8Array(32));
    map.set(-4, new Uint8Array(32));
    map.set(4, [8]); // key_ops = [derive bits]
    // Should not throw
    const d = extractPrivateKeyBytes(encode(map));
    assertEquals(d.length, 32);
  });
});
