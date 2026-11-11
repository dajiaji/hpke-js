/**
 * Result types and output formatting (console table / Markdown).
 */

import type { BundlerId } from "./bundlers/index.ts";
import type { LibId, Role } from "./libs.ts";
import type { Sizes } from "./measure.ts";
import type { JoseResult } from "./jose.ts";

export interface LibResult extends Sizes {
  /** Bytes in the minified output per source module (esbuild only). */
  modules?: Record<string, number>;
}

export interface Result {
  id: string;
  label: string;
  role: Role;
  packages: Record<LibId, string[]>;
  sizes: Partial<Record<BundlerId, Record<LibId, LibResult>>>;
}

export interface Meta {
  revision: string;
  /** Whether the bundles were checked by sealing and opening a message. */
  verified: boolean;
  bundlers: Partial<Record<BundlerId, string>>;
  panvaVersion: string;
  panvaNobleVersion: string;
  node: string;
}

const fmt = (n: number): string => n.toLocaleString("en-US");
const pkgs = (list: string[]): string =>
  list.map((p) => `\`${p}\``).join(" + ");
const ratio = (
  s: Record<LibId, LibResult>,
  format: "gzip" | "brotli",
): string => (s["@hpke"][format] / s["panva/hpke"][format]).toFixed(2);

export function printTable(results: Result[], bundlers: BundlerId[]): void {
  for (const format of ["gzip", "brotli"] as const) {
    console.log(`\n${format}`);
    console.table(
      results.map((r) => {
        const row: Record<string, string | number> = {
          suite: r.id,
          role: r.role,
        };
        for (const b of bundlers) {
          const s = r.sizes[b]!;
          row[`${b} @hpke`] = s["@hpke"][format];
          row[`${b} panva`] = s["panva/hpke"][format];
          row[`${b} ratio`] = ratio(s, format);
        }
        return row;
      }),
    );
  }
}

export function printModules(
  title: string,
  modules: Record<string, number>,
): void {
  console.log(`\n${title}`);
  for (const [path, bytes] of Object.entries(modules)) {
    console.log(`  ${String(bytes).padStart(7)}  ${path}`);
  }
}

export function toMarkdown(
  results: Result[],
  meta: Meta,
  bundlers: BundlerId[],
): string {
  const lines = [
    "# Bundle size benchmark",
    "",
    `- @hpke: \`@hpke/core\` + extensions, repository sources @ \`${meta.revision}\``,
    `- panva/hpke: \`hpke@${meta.panvaVersion}\` (+ \`@panva/hpke-noble@${meta.panvaNobleVersion}\` for ChaCha20Poly1305 / ML-KEM / X-Wing)`,
    "- `sideEffects: false` is honored for all packages on both sides",
    meta.verified
      ? "- HPKE and JOSE bundles verified by seal/open; OHTTP bundles by HTTP request/response round-trips"
      : "- **bundles NOT verified** (`--no-verify`)",
    "- sizes in bytes (min / gzip -9 / brotli -11); ratios = @hpke / panva",
    "",
    "Bundlers:",
    "",
    ...bundlers.map((b) => `- **${b}**: ${meta.bundlers[b]}`),
  ];
  for (const b of results.length ? bundlers : []) {
    lines.push("", `## ${b}`);
    for (const format of ["gzip", "brotli"] as const) {
      lines.push(
        "",
        `### ${format}`,
        "",
        `| Suite | Role | @hpke packages | @hpke min | @hpke ${format} | panva packages | panva min | panva ${format} | ratio |`,
        "| --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: |",
      );
      for (const r of results) {
        const s = r.sizes[b]!;
        const a = s["@hpke"];
        const p = s["panva/hpke"];
        lines.push(
          `| ${r.label} | ${r.role} | ${pkgs(r.packages["@hpke"])} | ${
            fmt(a.min)
          } | ${fmt(a[format])} | ${pkgs(r.packages["panva/hpke"])} | ${
            fmt(p.min)
          } | ${fmt(p[format])} | ${ratio(s, format)} |`,
        );
      }
    }
  }
  lines.push("");
  return lines.join("\n");
}

export function printJoseTable(
  results: JoseResult[],
  bundlers: BundlerId[],
): void {
  console.log("\nJOSE");
  console.table(bundlers.flatMap((b) =>
    results.map((r) => {
      const s = r.sizes[b]!;
      return {
        suite: r.id,
        role: r.role,
        bundler: b,
        min: s.min,
        gzip: s.gzip,
        br: s.brotli,
      };
    })
  ));
}

export function joseToMarkdown(
  results: JoseResult[],
  meta: Meta,
  bundlers: BundlerId[],
): string {
  if (results.length === 0) return "";
  const lines = [
    "",
    "## JOSE",
    "",
    `- @hpke/jose: repository sources @ \`${meta.revision}\``,
    "Sender imports a public JWK and encrypts a Compact JWE; recipient imports a private JWK and decrypts it.",
    "JOSE is reported independently of the panva HPKE comparison.",
    "Sizes in bytes (min / gzip -9 / brotli -11).",
  ];
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
      lines.push(
        `| ${r.label} | ${r.role} | ${
          pkgs(r.packages)
        } | ${s.min} | ${s.gzip} | ${s.brotli} |`,
      );
    }
  }
  lines.push("");
  return lines.join("\n");
}
