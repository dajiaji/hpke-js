/**
 * This file is based on noble-hashes (https://github.com/paulmillr/noble-hashes).
 *
 * noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-hashes/blob/4e358a46d682adfb005ae6314ec999f2513086b9/test/u64.test.ts
 */

import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { createHash, createHmac } from "node:crypto";

import { sha256, sha384, sha512 } from "../src/hash/sha2.ts";
import { sha3_256, sha3_512, shake128, shake256 } from "../src/hash/sha3.ts";
import { hmac } from "../src/hash/hmac.ts";
import { concatBytes, hexToBytes, utf8ToBytes } from "../src/utils/noble.ts";
import { repeat, TYPE_TEST } from "./utils.ts";

// NIST test vectors (https://www.di-mgt.com.au/sha_testvectors.html)
const NIST_VECTORS = [
  [1, utf8ToBytes("abc")],
  [1, utf8ToBytes("")],
  [1, utf8ToBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")],
  [
    1,
    utf8ToBytes(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ),
  ],
  [1000000, utf8ToBytes("a")],
  // Very slow, 1GB
  //[16777216, utf8ToBytes('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno')],
].map(([r, buf]) => [r, buf, repeat(buf as Uint8Array, r as number)]);

// Main idea: write 16k buffer with different values then test sliding window against node-js implementation
const testBuf = new Uint8Array(4096);
for (let i = 0; i < testBuf.length; i++) testBuf[i] = i;

const HASHES = {
  SHA256: {
    name: "SHA256",
    fn: sha256,
    obj: sha256.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(createHash("sha256").update(buf).digest()),
    node_obj: () => createHash("sha256"),
    nist: [
      "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",
      "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855",
      "248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1",
      "cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1",
      "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0",
      "50e72a0e 26442fe2 552dc393 8ac58658 228c0cbf b1d2ca87 2ae43526 6fcd055e",
    ],
  },
  SHA384: {
    name: "SHA384",
    fn: sha384,
    obj: sha384.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(createHash("sha384").update(buf).digest()),
    node_obj: () => createHash("sha384"),
    nist: [
      "cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7",
      "38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b",
      "3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6 b0455a8520bc4e6f 5fe95b1fe3c8452b",
      "09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712 fcc7c71a557e2db9 66c3e9fa91746039",
      "9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b 07b8b3dc38ecc4eb ae97ddd87f3d8985",
      "5441235cc0235341 ed806a64fb354742 b5e5c02a3c5cb71b 5f63fb793458d8fd ae599c8cd8884943 c04f11b31b89f023",
    ],
  },
  SHA512: {
    name: "SHA512",
    fn: sha512,
    obj: sha512.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(createHash("sha512").update(buf).digest()),
    node_obj: () => createHash("sha512"),
    nist: [
      "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f",
      "cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e",
      "204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445",
      "8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909",
      "e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b",
      "b47c933421ea2db1 49ad6e10fce6c7f9 3d0752380180ffd7 f4629a712134831d 77be6091b819ed35 2c2967a2e2d4fa50 50723c9630691f1a 05a7281dbe6c1086",
    ],
  },
  // Hmac as hash
  "HMAC-SHA256": {
    name: "HMAC-SHA256",
    fn: hmac.bind(null, sha256, new Uint8Array()),
    obj: hmac.create.bind(null, sha256, new Uint8Array()),
    node: (buf: Uint8Array) =>
      Uint8Array.from(
        createHmac("sha256", new Uint8Array()).update(buf).digest(),
      ),
    node_obj: () => createHmac("sha256", new Uint8Array()),
    // There is no official vectors, so we created them via:
    // > NIST_VECTORS.map((i) => createHmac('sha256', new Uint8Array()).update(i[2]).digest().toString('hex'))
    nist: [
      "fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351",
      "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
      "e31c6a8c54f60655956375893317d0fb2c55615355747b0379bb3772d27d59d4",
      "b303b8328d855cc51960c6f56cd98a12c5100d570b52019f54639a09e15bafaa",
      "cc9b6be49d1512557cef495770bb61e46fce6e83af89d385a038c8c050f4609d",
    ],
  },
  "HMAC-SHA512": {
    name: "HMAC-SHA512",
    fn: hmac.bind(null, sha512, new Uint8Array()),
    obj: hmac.create.bind(null, sha512, new Uint8Array()),
    node: (buf: Uint8Array) =>
      Uint8Array.from(
        createHmac("sha512", new Uint8Array()).update(buf).digest(),
      ),
    node_obj: () => createHmac("sha512", new Uint8Array()),
    // There is no official vectors, so we created them via:
    // > NIST_VECTORS.map((i) => createHmac('sha512', new Uint8Array()).update(i[2]).digest().toString('hex'))
    nist: [
      "29689f6b79a8dd686068c2eeae97fd8769ad3ba65cb5381f838358a8045a358ee3ba1739c689c7805e31734fb6072f87261d1256995370d55725cba00d10bdd0",
      "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
      "e0657364f9603a276d94930f90a6b19f3ce4001ab494c4fdf7ff541609e05d2e48ca6454a4390feb12b8eacebb503ba2517f5e2454d7d77e8b44d7cca8f752cd",
      "ece33db7448f63f4d460ac8b86bdf02fa6f5c3279a2a5d59df26827bec5315a44eb85d40ee4df3a7272a9596a0bc27091466724e9357183e554c9ec5fdf6d099",
      "59064f29e00b6a5cc55a3b69d9cfd3457ae70bd169b2b714036ae3a965805eb25a99ca221ade1aecebe6111d70697d1174a288cd1bb177de4a14f06eacc631d8",
    ],
  },
  SHA3_256: {
    name: "SHA3_256",
    fn: sha3_256,
    obj: sha3_256.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(
        createHash("sha3-256").update(buf).digest(),
      ),
    node_obj: () => createHash("sha3-256"),
    nist: [
      "3a985da74fe225b2 045c172d6bd390bd 855f086e3e9d525b 46bfe24511431532",
      "a7ffc6f8bf1ed766 51c14756a061d662 f580ff4de43b49fa 82d80a4b80f8434a",
      "41c0dba2a9d62408 49100376a8235e2c 82e1b9998a999e21 db32dd97496d3376",
      "916f6061fe879741 ca6469b43971dfdb 28b1a32dc36cb325 4e812be27aad1d18",
      "5c8875ae474a3634 ba4fd55ec85bffd6 61f32aca75c6d699 d0cdcb6c115891c1",
      "ecbbc42cbf296603 acb2c6bc0410ef43 78bafb24b710357f 12df607758b33e2b",
    ],
  },
  // SHA3_384: {
  //   name: "SHA3_384",
  //   fn: sha3_384,
  //   obj: sha3_384.create,
  //   node: (buf: Uint8Array) =>
  //     Uint8Array.from(
  //       createHash("sha3-384").update(buf).digest(),
  //     ),
  //   node_obj: () => createHash("sha3-384"),
  //   nist: [
  //     "ec01498288516fc9 26459f58e2c6ad8d f9b473cb0fc08c25 96da7cf0e49be4b2 98d88cea927ac7f5 39f1edf228376d25",
  //     "0c63a75b845e4f7d 01107d852e4c2485 c51a50aaaa94fc61 995e71bbee983a2a c3713831264adb47 fb6bd1e058d5f004",
  //     "991c665755eb3a4b 6bbdfb75c78a492e 8c56a22c5c4d7e42 9bfdbc32b9d4ad5a a04a1f076e62fea1 9eef51acd0657c22",
  //     "79407d3b5916b59c 3e30b09822974791 c313fb9ecc849e40 6f23592d04f625dc 8c709b98b43b3852 b337216179aa7fc7",
  //     "eee9e24d78c18553 37983451df97c8ad 9eedf256c6334f8e 948d252d5e0e7684 7aa0774ddb90a842 190d2c558b4b8340",
  //     "a04296f4fcaae148 71bb5ad33e28dcf6 9238b04204d9941b 8782e816d014bcb7 540e4af54f30d578 f1a1ca2930847a12",
  //   ],
  // },
  SHA3_512: {
    name: "SHA3_512",
    fn: sha3_512,
    obj: sha3_512.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(
        createHash("sha3-512").update(buf).digest(),
      ),
    node_obj: () => createHash("sha3-512"),
    nist: [
      "b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0",
      "a69f73cca23a9ac5 c8b567dc185a756e 97c982164fe25859 e0d1dcc1475c80a6 15b2123af1f5f94c 11e3e9402c3ac558 f500199d95b6d3e3 01758586281dcd26",
      "04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e",
      "afebb2ef542e6579 c50cad06d2e578f9 f8dd6881d7dc824d 26360feebf18a4fa 73e3261122948efc fd492e74e82e2189 ed0fb440d187f382 270cb455f21dd185",
      "3c3a876da14034ab 60627c077bb98f7e 120a2a5370212dff b3385a18d4f38859 ed311d0a9d5141ce 9cc5c66ee689b266 a8aa18ace8282a0e 0db596c90b0a7b87",
      "235ffd53504ef836 a1342b488f483b39 6eabbfe642cf78ee 0d31feec788b23d0 d18d5c339550dd59 58a500d4b95363da 1b5fa18affc1bab2 292dc63b7d85097c",
    ],
  },
  SHAKE128: {
    name: "SHAKE128",
    fn: shake128,
    obj: shake128.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(
        createHash("shake128", { outputLength: 16 }).update(buf).digest(),
      ),
    node_obj: () => createHash("shake128"),
    // There is no official vectors, so we created them via:
    // > NIST_VECTORS.map((i) => createHash('shake128').update(i[2]).digest('hex'))
    nist: [
      "5881092dd818bf5cf8a3ddb793fbcba7",
      "7f9c2ba4e88f827d616045507605853e",
      "1a96182b50fb8c7e74e0a707788f55e9",
      "7b6df6ff181173b6d7898d7ff63fb07b",
      "9d222c79c4ff9d092cf6ca86143aa411",
    ],
  },
  SHAKE256: {
    name: "SHAKE256",
    fn: shake256,
    obj: shake256.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(
        createHash("shake256", { outputLength: 32 }).update(buf).digest(),
      ),
    node_obj: () => createHash("shake256"),
    // There is no official vectors, so we created them via:
    // > NIST_VECTORS.map((i) => createHash('shake256').update(i[2]).digest('hex'))
    nist: [
      "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
      "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
      "4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e3329",
      "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf45",
      "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a",
    ],
  },
};

const BUF_768 = new Uint8Array(256 * 3);
// Fill with random data
for (let i = 0; i < (256 * 3) / 32; i++) {
  BUF_768.set(createHash("sha256").update(new Uint8Array(i)).digest(), i * 32);
}

Object.values(HASHES).forEach((hash) =>
  describe(hash.name, () => {
    // All hashes has NIST vectors, some generated manually
    it("NIST vectors", () => {
      for (let i = 0; i < NIST_VECTORS.length; i++) {
        if (!NIST_VECTORS[i]) continue;
        const [r, rbuf, buf] = NIST_VECTORS[i] as [
          number,
          Uint8Array,
          Uint8Array,
        ];
        assertEquals(
          hash.obj().update(buf).digest(),
          hexToBytes(hash.nist[i].replace(/ /g, "")),
          `vector ${i}`,
        );
        const tmp = hash.obj();
        for (let j = 0; j < r; j++) tmp.update(rbuf);
        assertEquals(
          tmp.digest(),
          hexToBytes(hash.nist[i].replace(/ /g, "")),
          `partial vector ${i}`,
        );
      }
    });
    it("accept data in compact call form (Uint8Array)", () => {
      assertEquals(
        hash.fn(utf8ToBytes("abc")),
        hexToBytes(hash.nist[0].replace(/ /g, "")),
      );
    });
    it("throw on update after digest", async () => {
      const tmp = hash.obj();
      tmp.update(utf8ToBytes("abc")).digest();
      await assertThrows(
        () => tmp.update(utf8ToBytes("abc")),
        Error,
      );
    });
    it("throw on second digest call", async () => {
      const tmp = hash.obj();
      tmp.update(utf8ToBytes("abc")).digest();
      await assertThrows(
        () => tmp.digest(),
        Error,
      );
    });
    it("throw on wrong argument type", async () => {
      // Allowed only: undefined (for compact form only), string, Uint8Array
      for (const t of TYPE_TEST.bytes) {
        await assertThrows(
          () => hash.fn(t),
          Error,
        );
        await assertThrows(
          () => hash.obj().update(t).digest(),
          Error,
        );
      }
      await assertThrows(
        () => hash.fn(undefined as unknown as Uint8Array),
        Error,
      );
      await assertThrows(
        () => hash.obj().update(undefined as unknown as Uint8Array).digest(),
        Error,
      );
      // for (const t of TYPE_TEST.opts) {
      //   await assertThrows(
      //     () => hash.fn(undefined as unknown as Uint8Array, t),
      //     Error,
      //   );
      // }
    });

    it("clone", () => {
      const exp = hash.fn(BUF_768);
      const t = hash.obj();
      t.update(BUF_768.subarray(0, 10));
      const t2 = t.clone();
      t2.update(BUF_768.subarray(10));
      assertEquals(t2.digest(), exp);
      t.update(BUF_768.subarray(10));
      assertEquals(t.digest(), exp);
    });

    it("partial", () => {
      const fnH = hash.fn(BUF_768);
      for (let i = 0; i < 256; i++) {
        const b1 = BUF_768.subarray(0, i);
        for (let j = 0; j < 256; j++) {
          const b2 = BUF_768.subarray(i, i + j);
          const b3 = BUF_768.subarray(i + j);
          assertEquals(concatBytes(b1, b2, b3), BUF_768);
          assertEquals(
            hash.obj().update(b1).update(b2).update(b3).digest(),
            fnH,
          );
        }
      }
    });
    // Same as before, but creates copy of each slice, which changes dataoffset of typed array
    // Catched bug in blake2
    it("partial (copy): partial", () => {
      const fnH = hash.fn(BUF_768);
      for (let i = 0; i < 256; i++) {
        const b1 = BUF_768.subarray(0, i).slice();
        for (let j = 0; j < 256; j++) {
          const b2 = BUF_768.subarray(i, i + j).slice();
          const b3 = BUF_768.subarray(i + j).slice();
          assertEquals(concatBytes(b1, b2, b3), BUF_768);
          assertEquals(
            hash.obj().update(b1).update(b2).update(b3).digest(),
            fnH,
          );
        }
      }
    });
    if (hash.node) {
      // if (!!process.versions.bun && ["BLAKE2s", "BLAKE2b"].includes(h)) {
      //   return;
      // }
      it("node.js cross-test", () => {
        for (let i = 0; i < testBuf.length; i++) {
          assertEquals(
            hash.obj().update(testBuf.subarray(0, i)).digest(),
            hash.node(testBuf.subarray(0, i)),
          );
        }
      });
      it("node.js cross-test chained", () => {
        const b = new Uint8Array([1, 2, 3]);
        let nodeH = hash.node(b);
        let nobleH = hash.fn(b);
        for (let i = 0; i < 256; i++) {
          nodeH = hash.node(nodeH);
          nobleH = hash.fn(nobleH);
          assertEquals(nodeH, nobleH);
        }
      });
      it("node.js cross-test partial", () => {
        assertEquals(hash.fn(BUF_768), hash.node(BUF_768));
      });
    }
  })
);
