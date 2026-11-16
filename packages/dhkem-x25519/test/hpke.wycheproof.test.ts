import { assert, assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import {
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
  HpkeError,
} from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import type { KemInterface } from "@hpke/core";
import { DhkemX25519HkdfSha256 as PackageDhkemX25519HkdfSha256 } from "../mod.ts";

type Result = "valid" | "invalid" | "acceptable";
interface Decryption {
  ct: string;
  aad: string;
  pt: string;
  result: Result;
}
interface TestCase extends Decryption {
  tcId: number;
  skRm: string;
  pkRm: string;
  enc: string;
  ikmE: string;
  info: string;
  decryptions: Decryption[];
}
interface TestGroup {
  kemId: number;
  kdfId: number;
  aeadId: number;
  tests: TestCase[];
}

const bytes = (s: string) =>
  Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
const hex = (b: ArrayBuffer): string =>
  Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0"))
    .join("");

function suiteFor(group: TestGroup, createKem: () => KemInterface) {
  const kdfs = {
    1: () => new HkdfSha256(),
    2: () => new HkdfSha384(),
    3: () => new HkdfSha512(),
  };
  const aeads = {
    1: () => new Aes128Gcm(),
    2: () => new Aes256Gcm(),
    3: () => new Chacha20Poly1305(),
  };
  const kem = createKem();
  const kdf = kdfs[group.kdfId as keyof typeof kdfs]?.();
  const aead = aeads[group.aeadId as keyof typeof aeads]?.();
  if (group.kemId !== 32 || !kdf || !aead) {
    throw new Error("Unknown HPKE parameters");
  }
  return { kem, suite: new CipherSuite({ kem, kdf, aead }) };
}

async function checkResult(result: Result, operation: () => Promise<void>) {
  let error: unknown;
  try {
    await operation();
  } catch (e) {
    error = e;
  }
  if (error !== undefined && !(error instanceof HpkeError)) throw error;
  if (result === "invalid") {
    assert(error instanceof HpkeError, "expected rejection");
  }
  if (result === "valid" && error !== undefined) throw error;
}

const implementations: {
  name: string;
  createKem: () => KemInterface;
}[] = [
  {
    name: "@hpke/core",
    createKem: () => new DhkemX25519HkdfSha256(),
  },
  {
    name: "@hpke/dhkem-x25519",
    createKem: () => new PackageDhkemX25519HkdfSha256(),
  },
];

// C2SP/wycheproof at 65ca494727a52944c204441c860b039e6786b99b, Apache-2.0.
for (const implementation of implementations) {
  for (const operation of ["decrypt", "encap", "sequence"]) {
    const file = `hpke_x25519_${operation}_test.json`;
    const data: { numberOfTests: number; testGroups: TestGroup[] } = JSON.parse(
      Deno.readTextFileSync(
        new URL(`./vectors/${file}`, import.meta.url),
      ),
    );
    describe(`${implementation.name} HPKE Wycheproof ${file}`, () => {
      assertEquals(
        data.testGroups.flatMap((group) => group.tests).length,
        data.numberOfTests,
      );
      for (const group of data.testGroups) {
        for (const tc of group.tests) {
          it(`tcId ${tc.tcId}`, async () => {
            const { kem, suite } = suiteFor(group, implementation.createKem);
            await checkResult(tc.result, async () => {
              if (operation === "encap") {
                const pk = await kem.deserializePublicKey(bytes(tc.pkRm));
                const ctx = await suite.createSenderContext({
                  recipientPublicKey: pk,
                  ekm: bytes(tc.ikmE),
                  info: bytes(tc.info),
                });
                assertEquals(hex(ctx.enc), tc.enc);
                assertEquals(
                  hex(await ctx.seal(bytes(tc.pt), bytes(tc.aad))),
                  tc.ct,
                );
              } else {
                const sk = await kem.deserializePrivateKey(bytes(tc.skRm));
                const ctx = await suite.createRecipientContext({
                  recipientKey: sk,
                  enc: bytes(tc.enc),
                  info: bytes(tc.info),
                });
                if (operation === "decrypt") {
                  assertEquals(
                    hex(await ctx.open(bytes(tc.ct), bytes(tc.aad))),
                    tc.pt,
                  );
                } else {
                  for (const item of tc.decryptions) {
                    await checkResult(item.result, async () => {
                      assertEquals(
                        hex(await ctx.open(bytes(item.ct), bytes(item.aad))),
                        item.pt,
                      );
                    });
                  }
                }
              }
            });
          });
        }
      }
    });
  }
}
