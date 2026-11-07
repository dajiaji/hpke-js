import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { hexToBytes } from "../src/utils/misc.ts";
import { __TEST as montTest } from "../src/curve/montgomery.ts";
import { x25519 } from "../src/curve/x25519.ts";

// Ported from noble-curves test/montgomery.test.ts:
// https://github.com/paulmillr/noble-curves/commit/c9a8031720412fad1006b4683dbffdf33d2cedf5

const P25519 = 2n ** 255n - 19n;
const P448 = 2n ** 448n - 2n ** 224n - 1n;

function toBytesLE(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

describe("Montgomery low-order keys", () => {
  // Every u whose order divides the cofactor, on the curve or on its
  // quadratic twist, plus non-canonical encodings of 0 and 1.
  const LOW_ORDER_25519 = [
    0n,
    1n,
    325606250916557431795983626356110631294008115727848805560023387167927233504n,
    39382357235489614581723060781553021112529911719440698176882885853963445705823n,
    P25519 - 1n,
    P25519,
    P25519 + 1n,
  ];

  // Fixed keys (RFC 7748 section 6.1): utils.randomSecretKey() needs a global
  // crypto, which Node.js 18 ESM builds do not provide.
  const SK = hexToBytes(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  );
  const PEER_PK = hexToBytes(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  );

  it("should accept an honest X25519 peer key", () => {
    assertEquals(x25519.getSharedSecret(SK, PEER_PK).length, 32);
  });

  for (const u of LOW_ORDER_25519) {
    it(`should reject low-order X25519 u=${u}`, () => {
      assertThrows(
        () => x25519.getSharedSecret(SK, toBytesLE(u, 32)),
        Error,
        "invalid private or public key received",
      );
    });
  }

  it("should reject a low-order peer key before touching the secret key", () => {
    // A malformed (31-byte) secret never reaches its length check.
    assertThrows(
      () => x25519.getSharedSecret(new Uint8Array(31), toBytesLE(1n, 32)),
      Error,
      "invalid private or public key received",
    );
  });
});

describe("Montgomery cswap", () => {
  const { cmask, cswap } = montTest;
  // 13 is prime and tiny, so edge cases (0, 1, P-1, equal inputs) are dense.
  const PRIMES = [P25519, P448, 13n];
  const mod = (a: bigint, P: bigint) => ((a % P) + P) % P;
  // Deterministic, so a failure reproduces exactly.
  let seed = 0x2545f491n;
  const rnd = (P: bigint) => {
    let acc = 0n;
    for (let i = 0; i < 8; i++) {
      seed = (seed * 6364136223846793005n + 1442695040888963407n) &
        ((1n << 64n) - 1n);
      acc = (acc << 64n) | seed;
    }
    return mod(acc, P);
  };

  it("cmask selects P / P + 1 from the low bit alone", () => {
    for (const P of PRIMES) {
      for (let trial = 0; trial < 32; trial++) {
        const k = rnd(1n << 512n);
        for (let t = 0n; t <= 512n; t++) {
          assertEquals(cmask(P, k >> t), P + ((k >> t) & 1n));
        }
        assertEquals(cmask(P, k), P + (k & 1n));
      }
      for (let v = 0n; v < 128n; v++) assertEquals(cmask(P, v), P + (v & 1n));
      // cswap's multiplier is never 0n or 1n.
      for (const v of [0n, 1n, 2n, 255n, 1n << 400n, (1n << 400n) + 1n]) {
        assertEquals(cmask(P, v) >= P, true);
      }
    }
  });

  it("cswap keeps on P and swaps on P + 1", () => {
    for (const P of PRIMES) {
      const keep = cmask(P, 0n);
      const swapMask = cmask(P, 1n);
      const swap = cswap(P);
      assertEquals([keep, swapMask], [P, P + 1n]);
      const vals = [0n, 1n, 2n, P - 1n, P - 2n, (P - 1n) / 2n];
      for (let i = 0; i < 24; i++) vals.push(rnd(P));
      for (const x of vals) {
        for (const y of vals) {
          assertEquals(swap(keep, x, y), { x_2: x, x_3: y });
          assertEquals(swap(swapMask, x, y), { x_2: y, x_3: x });
          // Higher bits of the cmask input must not leak into the selection.
          assertEquals(swap(cmask(P, 0xf0n), x, y), { x_2: x, x_3: y });
          assertEquals(swap(cmask(P, 0xffn), x, y), { x_2: y, x_3: x });
          for (const r of [swap(keep, x, y), swap(swapMask, x, y)]) {
            assertEquals(r.x_2 >= 0n && r.x_2 < P, true);
            assertEquals(r.x_3 >= 0n && r.x_3 < P, true);
          }
          const once = swap(swapMask, x, y);
          assertEquals(swap(swapMask, once.x_2, once.x_3), { x_2: x, x_3: y });
        }
      }
    }
  });

  it("cswap requires canonical inputs", () => {
    // Documented precondition: unreduced input yields a wrong representative.
    const P = 13n;
    const swap = cswap(P);
    assertEquals(swap(cmask(P, 0n), 14n, 3n), { x_2: 1n, x_3: 16n });
    assertEquals(swap(cmask(P, 0n), 1n, 3n), { x_2: 1n, x_3: 3n });
  });

  it("cswap drives the ladder exactly like the RFC 7748 reference", () => {
    // Swaps alone always compose to the identity over a full ladder (the
    // total swap count is even), so compare the state after every round:
    // a final-state check would pass even with every swap omitted.
    for (
      const [P, bits] of [
        [P25519, 255],
        [P448, 448],
      ] as const
    ) {
      const swap = cswap(P);
      for (let trial = 0; trial < 8; trial++) {
        const k = rnd(1n << BigInt(bits));
        // Reference: RFC 7748 section 5, carrying `swap` between rounds.
        let rx2 = rnd(P);
        let rx3 = rnd(P);
        let refSwap = 0n;
        // Implementation: bit t of (k XOR k>>1), no carried state.
        let x2 = rx2;
        let x3 = rx3;
        const kx = k ^ (k >> 1n);
        for (let t = BigInt(bits - 1); t >= 0n; t--) {
          const kt = (k >> t) & 1n;
          refSwap ^= kt;
          if (refSwap === 1n) [rx2, rx3] = [rx3, rx2];
          refSwap = kt;

          ({ x_2: x2, x_3: x3 } = swap(cmask(P, kx >> t), x2, x3));
          assertEquals([x2, x3], [rx2, rx3], `round t=${t}`);
        }
        if (refSwap === 1n) [rx2, rx3] = [rx3, rx2];
        ({ x_2: x2, x_3: x3 } = swap(cmask(P, k), x2, x3));
        assertEquals([x2, x3], [rx2, rx3], "trailing cswap");
      }
    }
  });
});
