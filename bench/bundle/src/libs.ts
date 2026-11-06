/**
 * Libraries under comparison, and the "typical application" entry point
 * source generated for each of them.
 *
 * - sender:    deserialize the recipient public key -> single-shot seal
 * - recipient: deserialize the recipient private key -> single-shot open
 */

import type { Suite, SuiteSpec } from "./suites.ts";

export const ROLES = ["sender", "recipient"] as const;
export type Role = (typeof ROLES)[number];

export type LibId = "@hpke" | "panva/hpke";

export interface Lib {
  readonly id: LibId;
  /** Generates the ESM source of the application entry point. */
  entry(suite: Suite, role: Role): string;
  /** Packages the application depends on for the suite. */
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
  entry(suite, role) {
    const imports = importsFor(suite.hpke, "@hpke/core");
    const { kem, kdf, aead } = suite.hpke;
    const ctor = `new CipherSuite({
  kem: new ${kem[1]}(),
  kdf: new ${kdf[1]}(),
  aead: new ${aead[1]}(),
})`;
    if (role === "sender") {
      return `${imports}
export async function seal(pkR, pt, aad) {
  const suite = ${ctor};
  const recipientPublicKey = await suite.kem.deserializePublicKey(pkR);
  const { enc, ct } = await suite.seal({ recipientPublicKey }, pt, aad);
  return { enc: new Uint8Array(enc), ct: new Uint8Array(ct) };
}
`;
    }
    return `${imports}
export async function open(skR, enc, ct, aad) {
  const suite = ${ctor};
  const recipientKey = await suite.kem.deserializePrivateKey(skR);
  return new Uint8Array(await suite.open({ recipientKey, enc }, ct, aad));
}
`;
  },
};

const panva: Lib = {
  id: "panva/hpke",
  packages: (suite) => packagesFor(suite.panva, "hpke"),
  entry(suite, role) {
    const imports = importsFor(suite.panva, "hpke");
    const { kem, kdf, aead } = suite.panva;
    const ctor = `new CipherSuite(${kem[1]}, ${kdf[1]}, ${aead[1]})`;
    if (role === "sender") {
      return `${imports}
export async function seal(pkR, pt, aad) {
  const suite = ${ctor};
  const pk = await suite.DeserializePublicKey(pkR);
  const { encapsulatedSecret, ciphertext } = await suite.Seal(pk, pt, { aad });
  return { enc: encapsulatedSecret, ct: ciphertext };
}
`;
    }
    return `${imports}
export async function open(skR, enc, ct, aad) {
  const suite = ${ctor};
  const sk = await suite.DeserializePrivateKey(skR);
  return await suite.Open(sk, enc, ct, { aad });
}
`;
  },
};

export const LIBS: readonly Lib[] = [hpke, panva];
