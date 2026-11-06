/**
 * Runtime verification of the generated bundles.
 *
 * For each suite, a recipient key pair is generated, then every sender bundle
 * seals a message and every recipient bundle must open it (cross-library).
 * This guarantees that the measured bundles are functional and interoperable,
 * not trivially tree-shaken away.
 */

import { CipherSuite } from "hpke";
import type { AEADFactory, KDFFactory, KEMFactory } from "hpke";
import { pathToFileURL } from "node:url";

import { LIBS } from "./libs.ts";
import type { LibId, Role } from "./libs.ts";
import type { Import, Suite } from "./suites.ts";

export type BundleFiles = Record<LibId, Record<Role, string>>;

type SealFn = (
  pkR: Uint8Array,
  pt: Uint8Array,
  aad: Uint8Array,
) => Promise<{ enc: Uint8Array; ct: Uint8Array }>;

type OpenFn = (
  skR: Uint8Array,
  enc: Uint8Array,
  ct: Uint8Array,
  aad: Uint8Array,
) => Promise<Uint8Array>;

async function load<T>([pkg, name]: Import): Promise<T> {
  const mod = (await import(pkg)) as Record<string, unknown>;
  const value = mod[name];
  if (value === undefined) {
    throw new Error(`${pkg} does not export ${name}`);
  }
  return value as T;
}

/** Generates a key pair with the (unbundled) panva/hpke suite definition. */
async function generateKeyPair(
  suite: Suite,
): Promise<{ pk: Uint8Array; sk: Uint8Array }> {
  const s = new CipherSuite(
    await load<KEMFactory>(suite.panva.kem),
    await load<KDFFactory>(suite.panva.kdf),
    await load<AEADFactory>(suite.panva.aead),
  );
  const kp = await s.GenerateKeyPair(true);
  return {
    pk: await s.SerializePublicKey(kp.publicKey),
    sk: await s.SerializePrivateKey(kp.privateKey),
  };
}

async function importBundle<T>(file: string, name: string): Promise<T> {
  const mod = (await import(pathToFileURL(file).href)) as Record<
    string,
    unknown
  >;
  return mod[name] as T;
}

export async function verify(suite: Suite, files: BundleFiles): Promise<void> {
  const { pk, sk } = await generateKeyPair(suite);
  const pt = new TextEncoder().encode("hello hpke bundle size bench");
  const aad = new TextEncoder().encode("aad");
  for (const sender of LIBS) {
    const seal = await importBundle<SealFn>(files[sender.id].sender, "seal");
    const { enc, ct } = await seal(pk, pt, aad);
    for (const recipient of LIBS) {
      const open = await importBundle<OpenFn>(
        files[recipient.id].recipient,
        "open",
      );
      const got = await open(sk, enc, ct, aad);
      if (Buffer.compare(got, pt) !== 0) {
        throw new Error(
          `${suite.id}: ${sender.id} -> ${recipient.id}: plaintext mismatch`,
        );
      }
    }
  }
}
