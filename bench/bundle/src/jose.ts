/** JOSE-HPKE Integrated Encryption sender/recipient bundles. */
import { generateKeyPairSync } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import type { Bundler, BundlerId } from "./bundlers/types.ts";
import { measure } from "./measure.ts";
import { DIST } from "./paths.ts";
import { printModules } from "./report.ts";
import type { LibResult } from "./report.ts";

export const JOSE_SUITE_ID = "jose-hpke3-x25519";
const LABEL = "JOSE / HPKE-3 / X25519 / HKDF-SHA256 / AES-128-GCM";
const ROLES = ["sender", "recipient"] as const;
type Role = (typeof ROLES)[number];

export interface JoseResult {
  id: string;
  label: string;
  role: Role;
  packages: string[];
  sizes: Partial<Record<BundlerId, LibResult>>;
}

type BundleFiles = Record<Role, string>;
type Jwk = { kty?: string; crv?: string; x?: string; d?: string };
type Seal = (jwk: Jwk, plaintext: Uint8Array) => Promise<string>;
type Open = (jwk: Jwk, jwe: string) => Promise<Uint8Array>;

/** Typical applications: import a JWK, then encrypt/decrypt a Compact JWE. */
function entry(role: Role): string {
  return role === "sender"
    ? `import { createJoseHpke3 } from "@hpke/jose";
export async function seal(jwk, plaintext) {
  const hpke = createJoseHpke3();
  return await hpke.seal(await hpke.importPublicJwk(jwk), plaintext);
}
`
    : `import { createJoseHpke3 } from "@hpke/jose";
export async function open(jwk, jwe) {
  const hpke = createJoseHpke3();
  return await hpke.open(await hpke.importPrivateJwk(jwk), jwe);
}
`;
}

export async function benchmarkJose(
  bundlers: readonly Bundler[],
  verify: boolean,
  analyze: boolean,
): Promise<JoseResult[]> {
  const results: JoseResult[] = ROLES.map((role) => ({
    id: JOSE_SUITE_ID,
    label: LABEL,
    role,
    packages: ["@hpke/jose"],
    sizes: {},
  }));
  for (const bundler of bundlers) {
    const files = {} as BundleFiles;
    for (const result of results) {
      const { code, modules } = await bundler.bundle(entry(result.role));
      const dir = join(DIST, bundler.id);
      const file = join(dir, `${JOSE_SUITE_ID}.${result.role}.mjs`);
      await mkdir(dir, { recursive: true });
      await writeFile(file, code);
      files[result.role] = file;
      result.sizes[bundler.id] = { ...measure(code), modules };
      if (analyze && modules !== undefined) {
        printModules(
          `${JOSE_SUITE_ID} / ${bundler.id} / ${result.role}`,
          modules,
        );
      }
    }
    if (verify) await verifyJose(files);
    process.stderr.write(
      `  ${verify ? "✔" : "-"} ${JOSE_SUITE_ID} (${bundler.id})\n`,
    );
  }
  return results;
}

async function verifyJose(files: BundleFiles): Promise<void> {
  const kp = generateKeyPairSync("x25519");
  const publicJwk = kp.publicKey.export({ format: "jwk" });
  const privateJwk = kp.privateKey.export({ format: "jwk" });
  const plaintext = new TextEncoder().encode(
    "hello jose hpke bundle size bench",
  );
  const seal = (await import(pathToFileURL(files.sender).href)).seal as Seal;
  const open = (await import(pathToFileURL(files.recipient).href)).open as Open;
  const jwe = await seal(publicJwk, plaintext);
  const got = await open(privateJwk, jwe);
  if (Buffer.compare(got, plaintext) !== 0) {
    throw new Error(`${JOSE_SUITE_ID}: plaintext mismatch`);
  }
}
