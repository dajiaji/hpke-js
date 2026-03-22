/**
 * Benchmark: self-contained ChaCha20-Poly1305 implementation vs @noble/ciphers
 *
 * Run: deno bench --allow-read bench/bench.ts
 */

import { chacha20poly1305 as noble } from "npm:@noble/ciphers@^1.3.0/chacha";
import { chacha20poly1305 as ours } from "../src/chacha/chacha.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const res = hex.match(/[\da-f]{2}/gi);
  if (!res) throw new Error("Invalid hex");
  return new Uint8Array(res.map((h) => parseInt(h, 16)));
}

// Fixed test data (deterministic benchmarks)
const KEY = hexToBytes(
  "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
);
const IV = hexToBytes("070000004041424344454647");
const AAD = hexToBytes("50515253c0c1c2c3c4c5c6c7");

// Different message sizes for benchmarking
const MSG_64 = new Uint8Array(64);
const MSG_1024 = new Uint8Array(1024);
const MSG_8192 = new Uint8Array(8192);
crypto.getRandomValues(MSG_64);
crypto.getRandomValues(MSG_1024);
crypto.getRandomValues(MSG_8192);

// Pre-encrypt for decryption benchmarks
const CT_64_NOBLE = noble(KEY, IV, AAD).encrypt(MSG_64);
const CT_1024_NOBLE = noble(KEY, IV, AAD).encrypt(MSG_1024);
const CT_8192_NOBLE = noble(KEY, IV, AAD).encrypt(MSG_8192);
const CT_64_OURS = ours(KEY, IV, AAD).encrypt(MSG_64);
const CT_1024_OURS = ours(KEY, IV, AAD).encrypt(MSG_1024);
const CT_8192_OURS = ours(KEY, IV, AAD).encrypt(MSG_8192);

// ---------------------------------------------------------------------------
// Encrypt 64 bytes
// ---------------------------------------------------------------------------

Deno.bench({
  name: "encrypt 64B - @noble/ciphers",
  group: "encrypt-64",
  baseline: true,
  fn() {
    noble(KEY, IV, AAD).encrypt(MSG_64);
  },
});

Deno.bench({
  name: "encrypt 64B - ours",
  group: "encrypt-64",
  fn() {
    ours(KEY, IV, AAD).encrypt(MSG_64);
  },
});

// ---------------------------------------------------------------------------
// Encrypt 1 KB
// ---------------------------------------------------------------------------

Deno.bench({
  name: "encrypt 1KB - @noble/ciphers",
  group: "encrypt-1k",
  baseline: true,
  fn() {
    noble(KEY, IV, AAD).encrypt(MSG_1024);
  },
});

Deno.bench({
  name: "encrypt 1KB - ours",
  group: "encrypt-1k",
  fn() {
    ours(KEY, IV, AAD).encrypt(MSG_1024);
  },
});

// ---------------------------------------------------------------------------
// Encrypt 8 KB
// ---------------------------------------------------------------------------

Deno.bench({
  name: "encrypt 8KB - @noble/ciphers",
  group: "encrypt-8k",
  baseline: true,
  fn() {
    noble(KEY, IV, AAD).encrypt(MSG_8192);
  },
});

Deno.bench({
  name: "encrypt 8KB - ours",
  group: "encrypt-8k",
  fn() {
    ours(KEY, IV, AAD).encrypt(MSG_8192);
  },
});

// ---------------------------------------------------------------------------
// Decrypt 64 bytes
// ---------------------------------------------------------------------------

Deno.bench({
  name: "decrypt 64B - @noble/ciphers",
  group: "decrypt-64",
  baseline: true,
  fn() {
    noble(KEY, IV, AAD).decrypt(CT_64_NOBLE);
  },
});

Deno.bench({
  name: "decrypt 64B - ours",
  group: "decrypt-64",
  fn() {
    ours(KEY, IV, AAD).decrypt(CT_64_OURS);
  },
});

// ---------------------------------------------------------------------------
// Decrypt 1 KB
// ---------------------------------------------------------------------------

Deno.bench({
  name: "decrypt 1KB - @noble/ciphers",
  group: "decrypt-1k",
  baseline: true,
  fn() {
    noble(KEY, IV, AAD).decrypt(CT_1024_NOBLE);
  },
});

Deno.bench({
  name: "decrypt 1KB - ours",
  group: "decrypt-1k",
  fn() {
    ours(KEY, IV, AAD).decrypt(CT_1024_OURS);
  },
});

// ---------------------------------------------------------------------------
// Decrypt 8 KB
// ---------------------------------------------------------------------------

Deno.bench({
  name: "decrypt 8KB - @noble/ciphers",
  group: "decrypt-8k",
  baseline: true,
  fn() {
    noble(KEY, IV, AAD).decrypt(CT_8192_NOBLE);
  },
});

Deno.bench({
  name: "decrypt 8KB - ours",
  group: "decrypt-8k",
  fn() {
    ours(KEY, IV, AAD).decrypt(CT_8192_OURS);
  },
});
