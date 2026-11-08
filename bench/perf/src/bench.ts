/**
 * Benchmark operations and the measurement loop.
 */

import type { Adapter, Key } from "./libs.ts";

export const OPS = ["keygen", "seal", "open", "ctx-seal"] as const;
export type Op = (typeof OPS)[number];

export const OP_DESCRIPTIONS: Record<Op, string> = {
  keygen: "Generate a key pair",
  seal: "Single-shot seal (Base mode): encap + key schedule + AEAD encrypt",
  open: "Single-shot open (Base mode): decap + key schedule + AEAD decrypt",
  "ctx-seal": "AEAD encrypt on an established sender context",
};

/** Input data shared by every library for a suite. */
export interface Fixture {
  /** Recipient public key, serialized. */
  pkR: Uint8Array;
  /** Recipient private key, serialized. */
  skR: Uint8Array;
  pt: Uint8Array;
  aad: Uint8Array;
}

export type Task = () => Promise<unknown>;

/**
 * Prepares the timed function for `op`. Key deserialization, the reference
 * ciphertext for `open` and the sender context for `ctx-seal` are set up
 * here, outside the measurement.
 */
export async function prepare(
  lib: Adapter,
  op: Op,
  f: Fixture,
): Promise<Task> {
  switch (op) {
    case "keygen":
      return () => lib.generateKeyPair();
    case "seal": {
      const pk: Key = await lib.deserializePublicKey(f.pkR);
      return () => lib.seal(pk, f.pt, f.aad);
    }
    case "open": {
      const pk: Key = await lib.deserializePublicKey(f.pkR);
      const sk: Key = await lib.deserializePrivateKey(f.skR);
      const { enc, ct } = await lib.seal(pk, f.pt, f.aad);
      return () => lib.open(sk, enc, ct, f.aad);
    }
    case "ctx-seal": {
      const pk: Key = await lib.deserializePublicKey(f.pkR);
      const ctx = await lib.setupSender(pk);
      return () => ctx.seal(f.pt, f.aad);
    }
  }
}

export interface Stats {
  /** Number of timed iterations. */
  samples: number;
  /** Operations per second (1000 / mean). */
  hz: number;
  /** Mean time per operation in milliseconds. */
  mean: number;
  /** Median time per operation in milliseconds. */
  p50: number;
  /** 99th percentile time per operation in milliseconds. */
  p99: number;
  /** Relative margin of error of the mean (95% confidence), in percent. */
  rme: number;
}

async function runFor(task: Task, ms: number, out: number[]): Promise<void> {
  const end = performance.now() + ms;
  let t = performance.now();
  do {
    await task();
    const now = performance.now();
    out.push(now - t);
    t = now;
  } while (t < end);
}

export async function warmup(task: Task, ms: number): Promise<void> {
  await runFor(task, ms, []);
}

/** Collects samples by running `task` for `ms` milliseconds. */
export async function sample(task: Task, ms: number): Promise<number[]> {
  const out: number[] = [];
  await runFor(task, ms, out);
  return out;
}

export function stats(samples: number[]): Stats {
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  const mean = sorted.reduce((a, b) => a + b, 0) / n;
  const variance = n > 1
    ? sorted.reduce((a, b) => a + (b - mean) ** 2, 0) / (n - 1)
    : 0;
  const at = (q: number) =>
    sorted[Math.min(n - 1, Math.max(0, Math.ceil(q * n) - 1))];
  return {
    samples: n,
    hz: 1000 / mean,
    mean,
    p50: at(0.5),
    p99: at(0.99),
    rme: (1.96 * Math.sqrt(variance / n) / mean) * 100,
  };
}
