import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { keyWords, open, seal, xorBlock } from "../src/chacha/chacha.ts";
import { poly1305Tag } from "../src/chacha/_poly1305.ts";

// Test vectors from RFC 8439:
// https://www.rfc-editor.org/rfc/rfc8439

function hexToBytes(hex: string): Uint8Array {
  const bytes = hex.replaceAll(/\s/g, "");
  if (bytes.length % 2 !== 0) throw new Error("invalid hex");
  return Uint8Array.from(
    bytes.match(/.{2}/g)!.map((byte) => parseInt(byte, 16)),
  );
}

// Places a copy of bytes at the given byteOffset in a fresh buffer.
function atOffset(bytes: Uint8Array, offset: number): Uint8Array {
  const buf = new Uint8Array(bytes.length + offset);
  buf.set(bytes, offset);
  return buf.subarray(offset);
}

const SUNSCREEN = new TextEncoder().encode(
  "Ladies and Gentlemen of the class of '99: If I could offer you only " +
    "one tip for the future, sunscreen would be it.",
);

// RFC 8439 Section 2.4.2
const ENC_KEY = hexToBytes(
  "000102030405060708090a0b0c0d0e0f" +
    "101112131415161718191a1b1c1d1e1f",
);
const ENC_NONCE = hexToBytes("000000000000004a00000000");
const ENC_CIPHERTEXT = hexToBytes(
  "6e2e359a2568f98041ba0728dd0d6981" +
    "e97e7aec1d4360c20a27afccfd9fae0b" +
    "f91b65c5524733ab8f593dabcd62b357" +
    "1639d624e65152ab8f530c359f0861d8" +
    "07ca0dbf500d6a6156a38e088a22b65e" +
    "52bc514d16ccf806818ce91ab7793736" +
    "5af90bbf74a35be6b40b8eedf2785e42" +
    "874d",
);

// RFC 8439 Section 2.8.2
const AEAD_KEY = hexToBytes(
  "808182838485868788898a8b8c8d8e8f" +
    "909192939495969798999a9b9c9d9e9f",
);
const AEAD_NONCE = hexToBytes("070000004041424344454647");
const AEAD_AAD = hexToBytes("50515253c0c1c2c3c4c5c6c7");
const AEAD_CIPHERTEXT = hexToBytes(
  "d31a8d34648e60db7b86afbc53ef7ec2" +
    "a4aded51296e08fea9e2b5a736ee62d6" +
    "3dbea45e8ca9671282fafb69da92728b" +
    "1a71de0a9e060b2905d6a5b67ecd3b36" +
    "92ddbd7f2d778b8c9803aee328091b58" +
    "fab324e4fad675945585808b4831d7bc" +
    "3ff4def08e4b7a9de576d26586cec64b" +
    "61161ae10b594f09e26a7e902ecbd0600691",
);

const EMPTY = new Uint8Array();

// The ChaCha20 keystream block for the given counter.
function chacha20Block(
  key: Uint8Array,
  nonce: Uint8Array,
  counter: number,
): Uint8Array {
  const n = new DataView(nonce.buffer, nonce.byteOffset, 12);
  const block = new Uint32Array(16);
  xorBlock(
    keyWords(key),
    n.getUint32(0, true),
    n.getUint32(4, true),
    n.getUint32(8, true),
    counter,
    block,
    0,
  );
  return new Uint8Array(block.buffer);
}

// RFC 8439 Section 2.8.2: the one-time Poly1305 key of the AEAD test vector.
const AEAD_POLY_KEY = hexToBytes(
  "7bac2b252db447af09b67a55a4e95584" +
    "0ae1d6731075d9eb2a9375783ed553ff",
);

describe("RFC 8439", () => {
  it("matches the ChaCha20 block function test vector", () => {
    const key = hexToBytes(
      "000102030405060708090a0b0c0d0e0f" +
        "101112131415161718191a1b1c1d1e1f",
    );
    const nonce = hexToBytes("000000090000004a00000000");

    assertEquals(
      chacha20Block(key, nonce, 1),
      hexToBytes(
        "10f1e7e4d13b5915500fdd1fa32071c4" +
          "c7d1f4c733c068030422aa9ac3d46c4e" +
          "d2826446079faa0914c2d705d98b02a2" +
          "b5129cd1de164eb9cbd083e8a2503c4e",
      ),
    );
  });

  it("XORs the ChaCha20 block into the output at the given word offset", () => {
    const out = Uint32Array.from({ length: 48 }, (_, i) => i * 0x01010101);
    const expected = out.slice();
    const block = new Uint32Array(chacha20Block(ENC_KEY, ENC_NONCE, 7).buffer);
    for (let i = 0; i < 16; i++) expected[16 + i] ^= block[i];
    const n = new DataView(ENC_NONCE.buffer);

    xorBlock(
      keyWords(ENC_KEY),
      n.getUint32(0, true),
      n.getUint32(4, true),
      n.getUint32(8, true),
      7,
      out,
      16,
    );

    assertEquals(out, expected);
  });

  it("matches the ChaCha20 encryption test vector", () => {
    // The AEAD encrypts with the block counter starting at 1, as in the
    // Section 2.4.2 example.
    assertEquals(
      seal(keyWords(ENC_KEY), ENC_NONCE, EMPTY, SUNSCREEN).subarray(
        0,
        SUNSCREEN.length,
      ),
      ENC_CIPHERTEXT,
    );
  });

  it("matches the Poly1305 key generation test vector", () => {
    const key = hexToBytes(
      "808182838485868788898a8b8c8d8e8f" +
        "909192939495969798999a9b9c9d9e9f",
    );
    const nonce = hexToBytes("000000000001020304050607");

    assertEquals(
      chacha20Block(key, nonce, 0).subarray(0, 32),
      hexToBytes(
        "8ad5a08b905f81cc815040274ab29471" +
          "a833b637e3fd0da508dbb8e2fdd1a646",
      ),
    );
    assertEquals(
      chacha20Block(AEAD_KEY, AEAD_NONCE, 0).subarray(0, 32),
      AEAD_POLY_KEY,
    );
  });

  it("matches the AEAD Poly1305 tag for the one-time key", () => {
    const ctLen = SUNSCREEN.length;
    const tag = AEAD_CIPHERTEXT.subarray(ctLen);

    // Only the first ctLen bytes of the ciphertext argument are authenticated.
    assertEquals(
      poly1305Tag(AEAD_POLY_KEY, AEAD_AAD, AEAD_CIPHERTEXT, ctLen),
      tag,
    );
    assertEquals(
      poly1305Tag(
        AEAD_POLY_KEY,
        AEAD_AAD,
        AEAD_CIPHERTEXT.subarray(0, ctLen),
        ctLen,
      ),
      tag,
    );
  });

  it("matches the generic Poly1305 for the Section 2.5.2 key and message", () => {
    // poly1305Tag() only authenticates the AEAD layout, so the Section 2.5.2
    // message "Cryptographic Forum Research Group" is zero-padded to 48 bytes
    // and followed by the lengths block (empty AAD). The expected tag is the
    // generic Poly1305 of @noble/ciphers v1.3.0 over those 64 bytes.
    const key = hexToBytes(
      "85d6be7857556d337f4452fe42d506a8" +
        "0103808afb0db2fd4abff6af4149f51b",
    );
    const message = new TextEncoder().encode(
      "Cryptographic Forum Research Group",
    );

    assertEquals(
      poly1305Tag(key, EMPTY, message, message.length),
      hexToBytes("e288a10ef6d82360da372d0a15afe1b6"),
    );
  });

  it("authenticates every AAD and ciphertext length around block boundaries", () => {
    const key = keyWords(AEAD_KEY);
    for (const aadLen of [0, 1, 15, 16, 17, 31, 32, 33]) {
      for (const len of [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129]) {
        const aad = Uint8Array.from({ length: aadLen }, (_, i) => i * 7);
        const msg = Uint8Array.from({ length: len }, (_, i) => i * 13);
        const ct = seal(key, AEAD_NONCE, aad, msg);
        assertEquals(open(key, AEAD_NONCE, aad, ct), msg);

        // Flipping any single bit of the AAD, ciphertext or tag must fail.
        for (let i = 0; i < ct.length; i++) {
          const bad = ct.slice();
          bad[i] ^= 1 << (i % 8);
          assertThrows(
            () => open(key, AEAD_NONCE, aad, bad),
            Error,
            "invalid tag",
          );
        }
        for (let i = 0; i < aadLen; i++) {
          const bad = aad.slice();
          bad[i] ^= 1 << (i % 8);
          assertThrows(
            () => open(key, AEAD_NONCE, bad, ct),
            Error,
            "invalid tag",
          );
        }
        // Dropping a byte of the AAD must fail.
        if (aadLen) {
          assertThrows(
            () => open(key, AEAD_NONCE, aad.subarray(1), ct),
            Error,
            "invalid tag",
          );
        }
      }
    }
  });

  it("matches the AEAD_CHACHA20_POLY1305 test vector", () => {
    const key = keyWords(AEAD_KEY);
    const ciphertext = seal(key, AEAD_NONCE, AEAD_AAD, SUNSCREEN);

    assertEquals(ciphertext, AEAD_CIPHERTEXT);
    assertEquals(open(key, AEAD_NONCE, AEAD_AAD, ciphertext), SUNSCREEN);
  });

  it("rejects invalid keys, nonces and short ciphertexts", () => {
    const key = keyWords(AEAD_KEY);
    for (const len of [0, 16, 31, 33]) {
      assertEquals(keyWords(new Uint8Array(len)).length, 0);
    }
    assertThrows(
      () => seal(new Uint32Array(7), AEAD_NONCE, EMPTY, EMPTY),
      Error,
      "invalid key length",
    );
    for (const len of [0, 8, 11, 13, 24]) {
      assertThrows(
        () => seal(key, new Uint8Array(len), EMPTY, EMPTY),
        Error,
        "invalid nonce length",
      );
      assertThrows(
        () => open(key, new Uint8Array(len), EMPTY, new Uint8Array(16)),
        Error,
        "invalid nonce length",
      );
    }
    assertThrows(
      () => open(key, AEAD_NONCE, EMPTY, new Uint8Array(15)),
      Error,
      "ciphertext too short",
    );
  });
});

describe("RFC 8439 with misaligned buffers", () => {
  for (const offset of [1, 2, 3]) {
    it(`AEAD handles all inputs at byteOffset ${offset}`, () => {
      const keyBytes = atOffset(AEAD_KEY, offset);
      const key = keyWords(keyBytes);
      const nonce = atOffset(AEAD_NONCE, offset);
      const aad = atOffset(AEAD_AAD, offset);
      const msg = atOffset(SUNSCREEN, offset);

      const ciphertext = seal(key, nonce, aad, msg);
      assertEquals(ciphertext, AEAD_CIPHERTEXT);

      const plaintext = open(
        key,
        nonce,
        aad,
        atOffset(AEAD_CIPHERTEXT, offset),
      );
      assertEquals(plaintext, SUNSCREEN);
      // Inputs must be left untouched.
      assertEquals(keyBytes, AEAD_KEY);
      assertEquals(nonce, AEAD_NONCE);
      assertEquals(aad, AEAD_AAD);
      assertEquals(msg, SUNSCREEN);
    });

    it(`AEAD returns fresh, exactly sized buffers at byteOffset ${offset}`, () => {
      const key = keyWords(AEAD_KEY);
      const msg = atOffset(SUNSCREEN, offset);
      const ciphertext = seal(key, AEAD_NONCE, AEAD_AAD, msg);
      assertEquals(ciphertext.byteOffset, 0);
      assertEquals(ciphertext.buffer.byteLength, SUNSCREEN.length + 16);

      const input = atOffset(AEAD_CIPHERTEXT, offset);
      const plaintext = open(key, AEAD_NONCE, AEAD_AAD, input);
      assertEquals(plaintext.byteOffset, 0);
      assertEquals(plaintext.buffer.byteLength, SUNSCREEN.length);
      assertEquals(input, AEAD_CIPHERTEXT);
    });
  }
});
