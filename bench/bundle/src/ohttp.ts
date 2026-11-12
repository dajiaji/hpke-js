/** OHTTP client/gateway bundles, including both request and response handling. */
import { generateKeyPairSync } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import type { Bundler, BundlerId } from "./bundlers/types.ts";
import { measure } from "./measure.ts";
import type { LibResult } from "./report.ts";
import { printModules } from "./report.ts";
import type { SuiteSpec } from "./suites.ts";
import { REPO_ROOT } from "./paths.ts";

export interface OhttpSuite extends SuiteSpec {
  readonly id: string;
  readonly label: string;
  readonly curve: "x25519" | "x448";
}

export const OHTTP_SUITES: readonly OhttpSuite[] = [
  {
    id: "ohttp-x25519-sha256-aes128gcm",
    label: "OHTTP / X25519 / HKDF-SHA256 / AES-128-GCM",
    curve: "x25519",
    kem: ["@hpke/dhkem-x25519", "DhkemX25519HkdfSha256"],
    kdf: ["@hpke/core", "HkdfSha256"],
    aead: ["@hpke/core", "Aes128Gcm"],
  },
  {
    id: "ohttp-x448-sha512-aes256gcm",
    label: "OHTTP / X448 / HKDF-SHA512 / AES-256-GCM",
    curve: "x448",
    kem: ["@hpke/dhkem-x448", "DhkemX448HkdfSha512"],
    kdf: ["@hpke/core", "HkdfSha512"],
    aead: ["@hpke/core", "Aes256Gcm"],
  },
];

export const OHTTP_ROLES = ["client", "gateway"] as const;
export type OhttpRole = typeof OHTTP_ROLES[number];

export interface OhttpResult {
  id: string;
  label: string;
  role: OhttpRole;
  packages: string[];
  sizes: Partial<Record<BundlerId, LibResult>>;
}

/** Input format also accepts role names from earlier benchmark reports. */
export type OhttpBaselineResult = Omit<OhttpResult, "role"> & {
  role: OhttpRole | "sender" | "recipient";
};

/** Normalize legacy baseline labels to the RFC 9458 client/gateway roles. */
export function normalizeOhttpBaseline(
  results: readonly OhttpBaselineResult[],
): OhttpResult[] {
  return results.map((result) => {
    const role = result.role === "sender"
      ? "client"
      : result.role === "recipient"
      ? "gateway"
      : result.role;
    if (role !== "client" && role !== "gateway") {
      throw new Error(`Unknown OHTTP baseline role: ${result.role}`);
    }
    return { ...result, role };
  });
}

/** Minimal application entry points; neither role imports the opposite role. */
function entry(suite: OhttpSuite, role: OhttpRole): string {
  const codec = JSON.stringify(join(REPO_ROOT, "packages/ohttp/src/bhttp.ts"));
  const imports = `
import { ${suite.kem[1]} as Kem } from "${suite.kem[0]}";
import { ${suite.kdf[1]} as Kdf } from "${suite.kdf[0]}";
import { ${suite.aead[1]} as Aead } from "${suite.aead[0]}";
`;
  if (role === "client") {
    return `${imports}
import { createOhttpClient, createStandardEncoding } from "@hpke/ohttp";
import { encodeRequest, decodeRequest, encodeResponse, decodeResponse } from ${codec};
export async function send(keyConfig, request) {
  const client = createOhttpClient({
    encoding: createStandardEncoding(),
    kem: new Kem(), kdf: new Kdf(), aead: new Aead(), keyConfig,
    relayUrl: "https://relay.example/",
  });
  const ctx = await client.encapsulateRequest(encodeRequest(request));
  return {
    encRequest: new Uint8Array(await new Response(ctx.body).arrayBuffer()),
    async decapsulateResponse(bytes) {
      const body = await ctx.decapsulateResponse([bytes]);
      return decodeResponse(body);
    },
  };
}
`;
  }
  return `${imports}
import { createOhttpGateway, createStandardEncoding } from "@hpke/ohttp";
import { encodeRequest, decodeRequest, encodeResponse, decodeResponse } from ${codec};
export async function createGateway(skR, pkR) {
  const kem = new Kem();
  const gateway = createOhttpGateway({
    encoding: createStandardEncoding(),
    keyId: 1, kem,
    privateKey: await kem.deserializePrivateKey(skR),
    publicKey: await kem.deserializePublicKey(pkR),
    kdfAeadPairs: [{ kdf: new Kdf(), aead: new Aead() }],
  });
  return {
    publicKeyConfig: gateway.publicKeyConfig,
    async decapsulateRequest(bytes) {
      const ctx = await gateway.decapsulateRequest([bytes]);
      return {
        request: await decodeRequest(ctx.body),
        async encapsulateResponse(response) {
          const result = await ctx.encapsulateResponse(encodeResponse(response));
          return new Uint8Array(await new Response(result.body).arrayBuffer());
        },
      };
    },
  };
}
`;
}

interface ClientContext {
  encRequest: Uint8Array;
  decapsulateResponse(data: Uint8Array): Promise<Response>;
}
interface Gateway {
  publicKeyConfig: Promise<Uint8Array>;
  decapsulateRequest(data: Uint8Array): Promise<{
    request: Request;
    encapsulateResponse(response: Response): Promise<Uint8Array>;
  }>;
}
type Send = (config: Uint8Array, request: Request) => Promise<ClientContext>;
type CreateGateway = (sk: Uint8Array, pk: Uint8Array) => Promise<Gateway>;
export type OhttpBundleFiles = Record<OhttpRole, string>;

/** Can also verify interoperability between before/after bundle pairs. */
export async function verifyOhttp(
  suite: OhttpSuite,
  bundles: readonly OhttpBundleFiles[],
): Promise<void> {
  const keys = suite.curve === "x25519"
    ? generateKeyPairSync("x25519")
    : generateKeyPairSync("x448");
  const sk = Buffer.from(
    keys.privateKey.export({ format: "jwk" }).d!,
    "base64url",
  );
  const pk = Buffer.from(
    keys.publicKey.export({ format: "jwk" }).x!,
    "base64url",
  );
  for (const gatewayBundle of bundles) {
    const { createGateway } = await import(
      pathToFileURL(gatewayBundle.gateway).href
    ) as { createGateway: CreateGateway };
    const gateway = await createGateway(sk, pk);
    for (const clientBundle of bundles) {
      const { send } = await import(
        pathToFileURL(clientBundle.client).href
      ) as {
        send: Send;
      };
      const ctx = await send(
        await gateway.publicKeyConfig,
        new Request("https://origin.example/resource?q=1", {
          method: "POST",
          headers: { "content-type": "text/plain", "x-bundle": "request" },
          body: "hello OHTTP request",
        }),
      );
      const received = await gateway.decapsulateRequest(ctx.encRequest);
      if (
        received.request.method !== "POST" ||
        received.request.url !== "https://origin.example/resource?q=1" ||
        received.request.headers.get("x-bundle") !== "request" ||
        await received.request.text() !== "hello OHTTP request"
      ) throw new Error(`${suite.id}: OHTTP request mismatch`);
      const encrypted = await received.encapsulateResponse(
        new Response("hello OHTTP response", {
          status: 201,
          headers: { "x-bundle": "response" },
        }),
      );
      const response = await ctx.decapsulateResponse(encrypted);
      if (
        response.status !== 201 ||
        response.headers.get("x-bundle") !== "response" ||
        await response.text() !== "hello OHTTP response"
      ) throw new Error(`${suite.id}: OHTTP response mismatch`);
    }
  }
}

export async function benchmarkOhttp(
  suites: readonly OhttpSuite[],
  bundlers: readonly Bundler[],
  dist: string,
  options: { verify: boolean; analyze: boolean },
): Promise<OhttpResult[]> {
  const results: OhttpResult[] = [];
  for (const suite of suites) {
    const rows = OHTTP_ROLES.map((role): OhttpResult => ({
      id: suite.id,
      label: suite.label,
      role,
      packages: [
        ...new Set([
          "@hpke/ohttp",
          suite.kem[0],
          suite.kdf[0],
          suite.aead[0],
        ]),
      ],
      sizes: {},
    }));
    for (const bundler of bundlers) {
      const files = {} as OhttpBundleFiles;
      for (const row of rows) {
        const { code, modules } = await bundler.bundle(entry(suite, row.role));
        const file = join(dist, bundler.id, `${suite.id}.${row.role}.mjs`);
        await mkdir(join(dist, bundler.id), { recursive: true });
        await writeFile(file, code);
        files[row.role] = file;
        row.sizes[bundler.id] = { ...measure(code), modules };
        if (options.analyze && modules !== undefined) {
          printModules(`${suite.id} / ${bundler.id} / ${row.role}`, modules);
        }
      }
      if (options.verify) await verifyOhttp(suite, [files]);
      process.stderr.write(
        `  ${options.verify ? "✔" : "-"} ${suite.id} (${bundler.id})\n`,
      );
    }
    results.push(...rows);
  }
  return results;
}

/** OHTTP has no equivalent in the panva HPKE benchmark. Report it separately. */
export function reportOhttp(
  results: OhttpResult[],
  bundlers: BundlerId[],
  before?: OhttpResult[],
): string {
  if (!results.length) return "";
  const lines = [
    "",
    "## OHTTP",
    "",
    "Client = request encryption + response decryption; gateway (Oblivious Gateway Resource) = request decryption + response encryption.",
    "Uses extension KEMs and core KDF/AEAD, matching the OHTTP sample. Sizes include BHTTP.",
    "OHTTP is reported independently of the panva HPKE comparison.",
  ];
  const rows: Record<string, string | number>[] = [];
  const comparisons: Record<string, string | number>[] = [];
  for (const b of bundlers) {
    lines.push(
      "",
      `### ${b}`,
      "",
      "| Suite | Role | Packages | min | gzip | br |",
      "| --- | --- | --- | ---: | ---: | ---: |",
    );
    for (const r of results) {
      const s = r.sizes[b]!;
      rows.push({ suite: r.id, role: r.role, bundler: b, ...measureRow(s) });
      lines.push(
        `| ${r.label} | ${r.role} | ${
          r.packages.map((p) => `\`${p}\``).join(" + ")
        } | ${s.min} | ${s.gzip} | ${s.brotli} |`,
      );
    }
    if (before === undefined) continue;
    lines.push(
      "",
      "Before / after (positive savings mean a smaller bundle):",
      "",
      "| Suite | Role | Before min | After min | Saved min | Before gzip | After gzip | Saved gzip | Before br | After br | Saved br |",
      "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    );
    for (const r of results) {
      const a = before.find((p) => p.id === r.id && p.role === r.role)
        ?.sizes[b];
      if (a === undefined) {
        throw new Error(`Missing OHTTP baseline: ${r.id}/${r.role}/${b}`);
      }
      const z = r.sizes[b]!;
      lines.push(
        `| ${r.label} | ${r.role} | ${a.min} | ${z.min} | ${
          a.min - z.min
        } | ${a.gzip} | ${z.gzip} | ${
          a.gzip - z.gzip
        } | ${a.brotli} | ${z.brotli} | ${a.brotli - z.brotli} |`,
      );
      comparisons.push({
        suite: r.id,
        role: r.role,
        bundler: b,
        "before min": a.min,
        "after min": z.min,
        "saved min": a.min - z.min,
        "before gzip": a.gzip,
        "after gzip": z.gzip,
        "saved gzip": a.gzip - z.gzip,
        "before br": a.brotli,
        "after br": z.brotli,
        "saved br": a.brotli - z.brotli,
      });
    }
  }
  console.table(rows);
  if (comparisons.length) console.table(comparisons);
  lines.push("");
  return lines.join("\n");
}

function measureRow(s: LibResult): Record<string, number> {
  return { min: s.min, gzip: s.gzip, br: s.brotli };
}
