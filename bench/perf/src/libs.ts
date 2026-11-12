/**
 * Libraries under comparison, and the adapter entry point source generated
 * for each of them.
 *
 * Every adapter exposes the same {@link Adapter} interface so that the
 * benchmark loop is identical for both libraries. The cipher suite object is
 * created once at module load; only the HPKE operations themselves are timed.
 */

import type { Suite, SuiteSpec } from "./suites.ts";

export type LibId = "@hpke" | "panva/hpke";

/** Opaque, library specific key object. */
export type Key = unknown;

export interface SenderContext {
  seal(pt: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
}

export interface Adapter {
  generateKeyPair(): Promise<{ publicKey: Key; privateKey: Key }>;
  serializePublicKey(key: Key): Promise<Uint8Array>;
  serializePrivateKey(key: Key): Promise<Uint8Array>;
  deserializePublicKey(bytes: Uint8Array): Promise<Key>;
  deserializePrivateKey(bytes: Uint8Array): Promise<Key>;
  seal(
    pk: Key,
    pt: Uint8Array,
    aad: Uint8Array,
  ): Promise<{ enc: Uint8Array; ct: Uint8Array }>;
  open(
    sk: Key,
    enc: Uint8Array,
    ct: Uint8Array,
    aad: Uint8Array,
  ): Promise<Uint8Array>;
  setupSender(pk: Key): Promise<SenderContext>;
}

export interface Lib {
  readonly id: LibId;
  /** Generates the ESM source of the adapter entry point. */
  entry(suite: Suite): string;
  /** Packages the adapter depends on for the suite. */
  packages(suite: Suite): string[];
}

/** Builds import statements for `spec`, adding `CipherSuite` from `basePkg`. */
function importsFor(spec: SuiteSpec, basePkg: string): string {
  const byPkg = new Map<string, Set<string>>([
    [basePkg, new Set(["CipherSuite"])],
  ]);
  for (const [pkg, name] of Object.values(spec) as SuiteSpec["kem"][]) {
    let names = byPkg.get(pkg);
    if (names === undefined) {
      names = new Set();
      byPkg.set(pkg, names);
    }
    names.add(name);
  }
  return [...byPkg]
    .map(([pkg, names]) =>
      `import { ${[...names].sort().join(", ")} } from "${pkg}";`
    )
    .join("\n");
}

function packagesFor(spec: SuiteSpec, basePkg: string): string[] {
  return [
    ...new Set([basePkg, spec.kem[0], spec.kdf[0], spec.aead[0]]),
  ];
}

const hpke: Lib = {
  id: "@hpke",
  packages: (suite) => packagesFor(suite.hpke, "@hpke/core"),
  entry(suite) {
    const { kem, kdf, aead } = suite.hpke;
    return `${importsFor(suite.hpke, "@hpke/core")}
const suite = new CipherSuite({
  kem: new ${kem[1]}(),
  kdf: new ${kdf[1]}(),
  aead: new ${aead[1]}(),
});
export const generateKeyPair = () => suite.kem.generateKeyPair();
export const serializePublicKey = async (key) =>
  new Uint8Array(await suite.kem.serializePublicKey(key));
export const serializePrivateKey = async (key) =>
  new Uint8Array(await suite.kem.serializePrivateKey(key));
export const deserializePublicKey = (bytes) =>
  suite.kem.deserializePublicKey(bytes);
export const deserializePrivateKey = (bytes) =>
  suite.kem.deserializePrivateKey(bytes);
export async function seal(recipientPublicKey, pt, aad) {
  const { enc, ct } = await suite.seal({ recipientPublicKey }, pt, aad);
  return { enc: new Uint8Array(enc), ct: new Uint8Array(ct) };
}
export async function open(recipientKey, enc, ct, aad) {
  return new Uint8Array(await suite.open({ recipientKey, enc }, ct, aad));
}
export async function setupSender(recipientPublicKey) {
  const ctx = await suite.createSenderContext({ recipientPublicKey });
  return {
    seal: async (pt, aad) => new Uint8Array(await ctx.seal(pt, aad)),
  };
}
`;
  },
};

const panva: Lib = {
  id: "panva/hpke",
  packages: (suite) => packagesFor(suite.panva, "hpke"),
  entry(suite) {
    const { kem, kdf, aead } = suite.panva;
    return `${importsFor(suite.panva, "hpke")}
const suite = new CipherSuite(${kem[1]}, ${kdf[1]}, ${aead[1]});
export const generateKeyPair = () => suite.GenerateKeyPair(true);
export const serializePublicKey = (key) => suite.SerializePublicKey(key);
export const serializePrivateKey = (key) => suite.SerializePrivateKey(key);
export const deserializePublicKey = (bytes) =>
  suite.DeserializePublicKey(bytes);
export const deserializePrivateKey = (bytes) =>
  suite.DeserializePrivateKey(bytes, false);
export async function seal(pk, pt, aad) {
  const { encapsulatedSecret, ciphertext } = await suite.Seal(pk, pt, { aad });
  return { enc: encapsulatedSecret, ct: ciphertext };
}
export function open(sk, enc, ct, aad) {
  return suite.Open(sk, enc, ct, { aad });
}
export async function setupSender(pk) {
  const { ctx } = await suite.SetupSender(pk);
  return { seal: (pt, aad) => ctx.Seal(pt, aad) };
}
`;
  },
};

export const LIBS: readonly Lib[] = [hpke, panva];
