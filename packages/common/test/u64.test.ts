/**
 * This file is based on noble-hashes (https://github.com/paulmillr/noble-hashes).
 *
 * noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-hashes/blob/4e358a46d682adfb005ae6314ec999f2513086b9/test/u64.test.ts
 */

import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import * as u64 from "../src/hash/u64.ts";

const U64_MASK = 2n ** 64n - 1n;
// const U32_MASK = (2 ** 32 - 1) | 0;
// Convert [u32, u32] to BigInt(u64)
const rotate_right = (word: bigint, shift: bigint) =>
  ((word >> shift) | (word << (64n - shift))) & U64_MASK;
const rotate_left = (word: bigint, shift: bigint) =>
  ((word >> (64n - shift)) + (word << shift)) % (1n << 64n);

// Convert BigInt(u64) -> [u32, u32]
// const big = (n) => {
//   return {
//     h: Number((n >> 32n) & BigInt(U32_MASK)) | 0,
//     l: Number(n & BigInt(U32_MASK)) | 0,
//   };
// };

describe("u64", () => {
  it("shr_small", () => {
    const val = [0x01234567, 0x89abcdef];
    const big = u64.toBig(val[0], val[1]);
    for (let i = 0; i < 32; i++) {
      const h = u64.shrSH(val[0], val[1], i);
      const l = u64.shrSL(val[0], val[1], i);
      assertEquals((big >> BigInt(i)) & U64_MASK, u64.toBig(h, l));
    }
  });

  // should('shr_big', () => {
  //   const val = [0x01234567, 0x89abcdef];
  //   const big = u64.toBig(...val);
  //   for (let i = 32; i < 64; i++) {
  //     const h = u64.shrBH(val[0], val[1], i);
  //     const l = u64.shrBL(val[0], val[1], i);
  //     deepStrictEqual((big >> BigInt(i)) & U64_MASK, u64.toBig(h, l));
  //   }
  // });

  it("rotr_small", () => {
    const val = [0x01234567, 0x89abcdef];
    const big = u64.toBig(val[0], val[1]);
    for (let i = 1; i < 32; i++) {
      const h = u64.rotrSH(val[0], val[1], i);
      const l = u64.rotrSL(val[0], val[1], i);
      assertEquals(rotate_right(big, BigInt(i)), u64.toBig(h, l));
    }
  });

  it("rotr32", () => {
    const val = [0x01234567, 0x89abcdef];
    const big = u64.toBig(val[0], val[1]);
    const h = u64.rotr32H(val[0], val[1]);
    const l = u64.rotr32L(val[0], val[1]);
    assertEquals(rotate_right(big, BigInt(32)), u64.toBig(h, l));
  });

  it("rotr_big", () => {
    const val = [0x01234567, 0x89abcdef];
    const big = u64.toBig(val[0], val[1]);
    for (let i = 33; i < 64; i++) {
      const h = u64.rotrBH(val[0], val[1], i);
      const l = u64.rotrBL(val[0], val[1], i);
      assertEquals(rotate_right(big, BigInt(i)), u64.toBig(h, l));
    }
  });

  it("rotl small", () => {
    const val = [0x01234567, 0x89abcdef];
    const big = u64.toBig(val[0], val[1]);
    for (let i = 1; i < 32; i++) {
      const h = u64.rotlSH(val[0], val[1], i);
      const l = u64.rotlSL(val[0], val[1], i);
      assertEquals(
        rotate_left(big, BigInt(i)),
        u64.toBig(h, l),
        `rotl_big(${i})`,
      );
    }
  });

  it("rotl big", () => {
    const val = [0x01234567, 0x89abcdef];
    const big = u64.toBig(val[0], val[1]);
    for (let i = 33; i < 64; i++) {
      const h = u64.rotlBH(val[0], val[1], i);
      const l = u64.rotlBL(val[0], val[1], i);
      assertEquals(
        rotate_left(big, BigInt(i)),
        u64.toBig(h, l),
        `rotl_big(${i})`,
      );
    }
  });
});
