/**
 * Result types and output formatting (console table / Markdown).
 */

import type { BundlerId } from "./bundlers/index.ts";
import type { LibId, Role } from "./libs.ts";
import type { Sizes } from "./measure.ts";

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
  bhttpVersion: string;
  node: string;
}

const fmt = (n: number): string => n.toLocaleString("en-US");
const pkgs = (list: string[]): string =>
  list.map((p) => `\`${p}\``).join(" + ");
const ratio = (s: Record<LibId, LibResult>): string =>
  (s["@hpke"].gzip / s["panva/hpke"].gzip).toFixed(2);

export function printTable(results: Result[], bundlers: BundlerId[]): void {
  console.table(
    results.map((r) => {
      const row: Record<string, string | number> = {
        suite: r.id,
        role: r.role,
      };
      for (const b of bundlers) {
        const s = r.sizes[b]!;
        row[`${b} @hpke gz`] = s["@hpke"].gzip;
        row[`${b} panva gz`] = s["panva/hpke"].gzip;
        row[`${b} ratio`] = ratio(s);
      }
      return row;
    }),
  );
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
    `- OHTTP BHTTP dependency: \`bhttp-js@${meta.bhttpVersion}\``,
    "- `sideEffects: false` is honored for all packages on both sides",
    meta.verified
      ? "- HPKE bundles verified by seal/open; OHTTP bundles by HTTP request/response round-trips"
      : "- **bundles NOT verified** (`--no-verify`)",
    "- sizes in bytes (min / gzip -9 / brotli -11); ratio = @hpke gzip / panva gzip",
    "",
    "Bundlers:",
    "",
    ...bundlers.map((b) => `- **${b}**: ${meta.bundlers[b]}`),
  ];
  for (const b of results.length ? bundlers : []) {
    lines.push(
      "",
      `## ${b}`,
      "",
      "| Suite | Role | @hpke packages | @hpke min | @hpke gzip | @hpke br | panva packages | panva min | panva gzip | panva br | ratio |",
      "| --- | --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |",
    );
    for (const r of results) {
      const s = r.sizes[b]!;
      const a = s["@hpke"];
      const p = s["panva/hpke"];
      lines.push(
        `| ${r.label} | ${r.role} | ${pkgs(r.packages["@hpke"])} | ${
          fmt(a.min)
        } | ${fmt(a.gzip)} | ${fmt(a.brotli)} | ${
          pkgs(r.packages["panva/hpke"])
        } | ${fmt(p.min)} | ${fmt(p.gzip)} | ${fmt(p.brotli)} | ${ratio(s)} |`,
      );
    }
  }
  lines.push("");
  return lines.join("\n");
}
