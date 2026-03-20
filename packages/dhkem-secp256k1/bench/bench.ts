/**
 * Benchmark: self-contained secp256k1 implementation vs @noble/curves
 *
 * Run: deno bench --allow-read bench/bench.ts
 */

import { secp256k1 as noble } from "npm:@noble/curves@^1.9.7/secp256k1";
import { Secp256k1 } from "../src/secp256k1.ts";
import { HkdfSha256 } from "../src/hkdfSha256.ts";
import { XCryptoKey } from "@hpke/common";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const res = hex.match(/[\da-f]{2}/gi);
  if (!res) throw new Error("Invalid hex");
  return new Uint8Array(res.map((h) => parseInt(h, 16)));
}

// Fixed test keys (deterministic benchmarks)
const SK_HEX =
  "f4b7ff7cccc98813a69fae3df222bfe3f4e28f764bf91b4a10d8096ce446b254";
const SK_BYTES = hexToBytes(SK_HEX);
const PK_NOBLE = noble.getPublicKey(SK_BYTES); // compressed 33 bytes

const SK2_HEX =
  "a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a";
const SK2_BYTES = hexToBytes(SK2_HEX);
const PK2_NOBLE = noble.getPublicKey(SK2_BYTES);

// Pre-import keys for ours implementation
const secp = new Secp256k1(new HkdfSha256());
const ourSk = new XCryptoKey("ECDH", SK_BYTES, "private", ["deriveBits"]);
const ourPk = new XCryptoKey("ECDH", PK2_NOBLE, "public");
const ourSk2 = new XCryptoKey("ECDH", SK2_BYTES, "private", ["deriveBits"]);
const ourPk1 = new XCryptoKey("ECDH", PK_NOBLE, "public");

// ---------------------------------------------------------------------------
// getPublicKey: derive compressed public key from private key
// ---------------------------------------------------------------------------

Deno.bench({
  name: "getPublicKey - @noble/curves",
  group: "getPublicKey",
  baseline: true,
  fn() {
    noble.getPublicKey(SK_BYTES);
  },
});

Deno.bench({
  name: "getPublicKey - ours",
  group: "getPublicKey",
  async fn() {
    await secp.derivePublicKey(ourSk);
  },
});

// ---------------------------------------------------------------------------
// ECDH: compute shared secret
// ---------------------------------------------------------------------------

Deno.bench({
  name: "ECDH (getSharedSecret) - @noble/curves",
  group: "ECDH",
  baseline: true,
  fn() {
    noble.getSharedSecret(SK_BYTES, PK2_NOBLE);
  },
});

Deno.bench({
  name: "ECDH (dh) - ours",
  group: "ECDH",
  async fn() {
    await secp.dh(ourSk, ourPk);
  },
});

// ---------------------------------------------------------------------------
// Full key-pair generation (including random number generation)
// ---------------------------------------------------------------------------

Deno.bench({
  name: "generateKeyPair - @noble/curves",
  group: "generateKeyPair",
  baseline: true,
  fn() {
    const sk = noble.utils.randomPrivateKey();
    noble.getPublicKey(sk);
  },
});

Deno.bench({
  name: "generateKeyPair - ours",
  group: "generateKeyPair",
  async fn() {
    await secp.generateKeyPair();
  },
});

// ---------------------------------------------------------------------------
// Full ECDH flow: generateKeyPair + ECDH
// ---------------------------------------------------------------------------

Deno.bench({
  name: "keygen + ECDH - @noble/curves",
  group: "full-flow",
  baseline: true,
  fn() {
    const sk = noble.utils.randomPrivateKey();
    noble.getSharedSecret(sk, PK2_NOBLE);
  },
});

Deno.bench({
  name: "keygen + ECDH - ours",
  group: "full-flow",
  async fn() {
    const kp = await secp.generateKeyPair();
    await secp.dh(kp.privateKey, ourPk);
  },
});
