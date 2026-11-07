import { assertEquals, assertStrictEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { chacha20, chacha20poly1305 } from "../src/chacha/chacha.ts";
import { Poly1305 } from "../src/chacha/_poly1305.ts";

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

describe("RFC 8439", () => {
  it("matches the ChaCha20 block function test vector", () => {
    const key = hexToBytes(
      "000102030405060708090a0b0c0d0e0f" +
        "101112131415161718191a1b1c1d1e1f",
    );
    const nonce = hexToBytes("000000090000004a00000000");
    const block = chacha20(key, nonce, new Uint8Array(64), undefined, 1);

    assertEquals(
      block,
      hexToBytes(
        "10f1e7e4d13b5915500fdd1fa32071c4" +
          "c7d1f4c733c068030422aa9ac3d46c4e" +
          "d2826446079faa0914c2d705d98b02a2" +
          "b5129cd1de164eb9cbd083e8a2503c4e",
      ),
    );
  });

  it("matches the ChaCha20 encryption test vector", () => {
    assertEquals(
      chacha20(ENC_KEY, ENC_NONCE, SUNSCREEN, undefined, 1),
      ENC_CIPHERTEXT,
    );
  });

  it("matches the Poly1305 test vector", () => {
    const key = hexToBytes(
      "85d6be7857556d337f4452fe42d506a8" +
        "0103808afb0db2fd4abff6af4149f51b",
    );
    const message = new TextEncoder().encode(
      "Cryptographic Forum Research Group",
    );
    const tag = new Poly1305(key).update(message).digest();

    assertEquals(tag, hexToBytes("a8061dc1305136c6c22b8baf0c0127a9"));
  });

  it("matches the Poly1305 key generation test vector", () => {
    const key = hexToBytes(
      "808182838485868788898a8b8c8d8e8f" +
        "909192939495969798999a9b9c9d9e9f",
    );
    const nonce = hexToBytes("000000000001020304050607");
    const oneTimeKey = chacha20(
      key,
      nonce,
      new Uint8Array(64),
      undefined,
      0,
    ).subarray(0, 32);

    assertEquals(
      oneTimeKey,
      hexToBytes(
        "8ad5a08b905f81cc815040274ab29471" +
          "a833b637e3fd0da508dbb8e2fdd1a646",
      ),
    );
  });

  it("matches the Poly1305 vector across incremental update boundaries", () => {
    const key = hexToBytes(
      "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
    );
    const message = new TextEncoder().encode(
      "Cryptographic Forum Research Group",
    );
    const expected = hexToBytes("a8061dc1305136c6c22b8baf0c0127a9");
    for (const size of [1, 15, 16, 17, 34]) {
      const mac = new Poly1305(key);
      for (let pos = 0; pos < message.length; pos += size) {
        mac.update(message.subarray(pos, pos + size));
      }
      assertEquals(mac.digest(), expected);
      assertThrows(() => mac.digest(), Error, "already been called");
      assertThrows(() => mac.update(message), Error, "already been called");
    }
  });

  it("matches the AEAD_CHACHA20_POLY1305 test vector", () => {
    const ciphertext = chacha20poly1305(AEAD_KEY, AEAD_NONCE, AEAD_AAD)
      .encrypt(SUNSCREEN);

    assertEquals(ciphertext, AEAD_CIPHERTEXT);
    assertEquals(
      chacha20poly1305(AEAD_KEY, AEAD_NONCE, AEAD_AAD).decrypt(ciphertext),
      SUNSCREEN,
    );
  });
});

describe("RFC 8439 with misaligned buffers", () => {
  for (const offset of [1, 2, 3]) {
    it(`ChaCha20 handles key/nonce/data/output at byteOffset ${offset}`, () => {
      const key = atOffset(ENC_KEY, offset);
      const nonce = atOffset(ENC_NONCE, offset);
      const data = atOffset(SUNSCREEN, offset);
      const output = atOffset(new Uint8Array(SUNSCREEN.length), offset);

      const res = chacha20(key, nonce, data, output, 1);

      assertEquals(res, ENC_CIPHERTEXT);
      // Inputs must be left untouched.
      assertEquals(key, ENC_KEY);
      assertEquals(nonce, ENC_NONCE);
      assertEquals(data, SUNSCREEN);
    });

    it(`ChaCha20 encrypts in place at byteOffset ${offset}`, () => {
      const buf = atOffset(SUNSCREEN, offset);

      chacha20(ENC_KEY, ENC_NONCE, buf, buf, 1);

      assertEquals(buf, ENC_CIPHERTEXT);
    });

    it(`ChaCha20 handles aligned data with output at byteOffset ${offset}`, () => {
      const output = atOffset(new Uint8Array(SUNSCREEN.length), offset);

      chacha20(ENC_KEY, ENC_NONCE, SUNSCREEN.slice(), output, 1);

      assertEquals(output, ENC_CIPHERTEXT);
    });

    it(`AEAD handles all inputs at byteOffset ${offset}`, () => {
      const key = atOffset(AEAD_KEY, offset);
      const nonce = atOffset(AEAD_NONCE, offset);
      const aad = atOffset(AEAD_AAD, offset);

      const ciphertext = chacha20poly1305(key, nonce, aad).encrypt(
        atOffset(SUNSCREEN, offset),
      );
      assertEquals(ciphertext, AEAD_CIPHERTEXT);

      const plaintext = chacha20poly1305(key, nonce, aad).decrypt(
        atOffset(AEAD_CIPHERTEXT, offset),
      );
      assertEquals(plaintext, SUNSCREEN);
      assertEquals(nonce, AEAD_NONCE);
    });

    it(`AEAD writes to supplied output buffers at byteOffset ${offset}`, () => {
      const output = atOffset(new Uint8Array(AEAD_CIPHERTEXT.length), offset);
      assertStrictEquals(
        chacha20poly1305(AEAD_KEY, AEAD_NONCE, AEAD_AAD).encrypt(
          SUNSCREEN,
          output,
        ),
        output,
      );
      assertEquals(output, AEAD_CIPHERTEXT);
      const plaintext = output.subarray(0, SUNSCREEN.length);
      assertStrictEquals(
        chacha20poly1305(AEAD_KEY, AEAD_NONCE, AEAD_AAD).decrypt(
          output,
          plaintext,
        ),
        plaintext,
      );
      assertEquals(plaintext, SUNSCREEN);
    });
  }
});
