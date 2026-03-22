/**
 * Benchmark: self-contained X25519 implementation vs @noble/curves
 *
 * Run: deno bench --allow-read bench/bench.ts
 */

import { x25519 as noble } from "npm:@noble/curves@^1.9.7/ed25519";
import { X25519 } from "../src/dhkemX25519.ts";
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
  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const SK_BYTES = hexToBytes(SK_HEX);
const PK_NOBLE = noble.getPublicKey(SK_BYTES); // 32 bytes

const SK2_HEX =
  "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const SK2_BYTES = hexToBytes(SK2_HEX);
const PK2_NOBLE = noble.getPublicKey(SK2_BYTES);

// Pre-import keys for ours implementation
const x = new X25519(new HkdfSha256());
const ourSk = new XCryptoKey("X25519", SK_BYTES, "private", ["deriveBits"]);
const ourPk = new XCryptoKey("X25519", PK2_NOBLE, "public");
const ourSk2 = new XCryptoKey("X25519", SK2_BYTES, "private", ["deriveBits"]);
const _ourPk1 = new XCryptoKey("X25519", PK_NOBLE, "public");

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
