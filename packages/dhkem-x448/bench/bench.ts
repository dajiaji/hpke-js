/**
 * Benchmark: self-contained X448 implementation vs @noble/curves
 *
 * Run: deno bench --allow-read bench/bench.ts
 */

import { x448 as noble } from "npm:@noble/curves@^1.9.7/ed448";
import { X448 } from "../src/dhkemX448.ts";
import { HkdfSha512 } from "../src/hkdfSha512.ts";
import { XCryptoKey } from "@hpke/common";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const res = hex.match(/[\da-f]{2}/gi);
  if (!res) throw new Error("Invalid hex");
  return new Uint8Array(res.map((h) => parseInt(h, 16)));
}

// Fixed test keys (deterministic benchmarks) - from RFC 7748 Section 6.2
const SK_HEX =
  "9a8f4925d1519f5775cf46b04b5800d4" +
  "ee9ee8bae8bc5565d498c28d" +
  "d9c9baf574a94197448973910063" +
  "82a6f127ab1d9ac2d8c0a598726b";
const SK_BYTES = hexToBytes(SK_HEX);
const PK_NOBLE = noble.getPublicKey(SK_BYTES); // 56 bytes

const SK2_HEX =
  "1c306a7ac2a0e2e0990b294470cba339" +
  "e6453772b075811d8fad0d1d" +
  "6927c120bb5ee8972b0d3e21" +
  "374c9c921b09d1b0366f10b65173992d";
const SK2_BYTES = hexToBytes(SK2_HEX);
const PK2_NOBLE = noble.getPublicKey(SK2_BYTES);

// Pre-import keys for ours implementation
const x = new X448(new HkdfSha512());
const ourSk = new XCryptoKey("X448", SK_BYTES, "private", ["deriveBits"]);
const ourPk = new XCryptoKey("X448", PK2_NOBLE, "public");
const ourSk2 = new XCryptoKey("X448", SK2_BYTES, "private", ["deriveBits"]);
const _ourPk1 = new XCryptoKey("X448", PK_NOBLE, "public");

// Suppress unused variable warning
void ourSk2;

// ---------------------------------------------------------------------------
// getPublicKey: derive public key from private key
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
    await x.derivePublicKey(ourSk);
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
    await x.dh(ourSk, ourPk);
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
    await x.generateKeyPair();
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
    noble.getPublicKey(sk);
    noble.getSharedSecret(sk, PK2_NOBLE);
  },
});

Deno.bench({
  name: "keygen + ECDH - ours",
  group: "full-flow",
  async fn() {
    const kp = await x.generateKeyPair();
    await x.dh(kp.privateKey, ourPk);
  },
});
