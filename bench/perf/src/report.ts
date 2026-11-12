/**
 * Result types and output formatting (console table / Markdown).
 */

import type { Op } from "./bench.ts";
import { OP_DESCRIPTIONS } from "./bench.ts";
import type { Stats } from "./bench.ts";
import type { LibId } from "./libs.ts";

export interface Result {
  id: string;
  label: string;
  op: Op;
  packages: Record<LibId, string[]>;
  stats: Record<LibId, Stats>;
}

export interface Meta {
  revision: string;
  build: string;
  panvaVersion: string;
  panvaNobleVersion: string;
  node: string;
  platform: string;
  cpu: string;
  /** Measurement time per library, suite and operation (ms). */
  time: number;
  /** Warm-up time per library, suite and operation (ms). */
  warmup: number;
  /** Number of alternating measurement rounds. */
  rounds: number;
  /** Plaintext length in bytes. */
  payload: number;
}

const ops = (hz: number): string =>
  hz >= 100
    ? Math.round(hz).toLocaleString("en-US")
    : hz.toLocaleString("en-US", { maximumFractionDigits: 1 });
const time = (ms: number): string =>
  ms >= 1 ? `${ms.toFixed(2)} ms` : `${(ms * 1000).toFixed(1)} µs`;
const pct = (v: number): string => `±${v.toFixed(1)}%`;
const pkgs = (list: string[]): string =>
  list.map((p) => `\`${p}\``).join(" + ");
export const ratio = (r: Result): string =>
  (r.stats["@hpke"].hz / r.stats["panva/hpke"].hz).toFixed(2);

export function printTable(results: Result[], opList: readonly Op[]): void {
  for (const op of opList) {
    const rows = results.filter((r) => r.op === op);
    if (rows.length === 0) continue;
    console.log(`\n${op}: ${OP_DESCRIPTIONS[op]} (ops/s)`);
    console.table(rows.map((r) => {
      const a = r.stats["@hpke"];
      const p = r.stats["panva/hpke"];
      return {
        suite: r.id,
        "@hpke": ops(a.hz),
        "@hpke rme": pct(a.rme),
        panva: ops(p.hz),
        "panva rme": pct(p.rme),
        ratio: ratio(r),
      };
    }));
  }
}

export function toMarkdown(
  results: Result[],
  meta: Meta,
  opList: readonly Op[],
): string {
  const lines = [
    "# Performance benchmark",
    "",
    `- @hpke: \`@hpke/core\` + extensions, repository sources @ \`${meta.revision}\``,
    `- panva/hpke: \`hpke@${meta.panvaVersion}\` (+ \`@panva/hpke-noble@${meta.panvaNobleVersion}\` for ChaCha20Poly1305 / ML-KEM / X-Wing)`,
    `- Runtime: Node.js ${meta.node} (${meta.platform}), ${meta.cpu}`,
    `- Build: ${meta.build}`,
    `- ${meta.rounds} alternating round(s) of ${meta.time} ms per library after ${meta.warmup} ms warm-up; plaintext ${meta.payload} bytes, AAD 16 bytes`,
    "- ops/s = 1000 / mean; ratio = @hpke ops/s / panva ops/s (> 1: @hpke is faster)",
    "",
    "## Suites",
    "",
    "| Suite | @hpke packages | panva packages |",
    "| --- | --- | --- |",
  ];
  const seen = new Set<string>();
  for (const r of results) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    lines.push(
      `| ${r.label} | ${pkgs(r.packages["@hpke"])} | ${
        pkgs(r.packages["panva/hpke"])
      } |`,
    );
  }
  for (const op of opList) {
    const rows = results.filter((r) => r.op === op);
    if (rows.length === 0) continue;
    lines.push(
      "",
      `## ${op}`,
      "",
      `${OP_DESCRIPTIONS[op]}.`,
      "",
      "| Suite | @hpke ops/s | @hpke mean | panva ops/s | panva mean | ratio |",
      "| --- | ---: | ---: | ---: | ---: | ---: |",
    );
    for (const r of rows) {
      const a = r.stats["@hpke"];
      const p = r.stats["panva/hpke"];
      lines.push(
        `| ${r.label} | ${ops(a.hz)} ${pct(a.rme)} | ${time(a.mean)} | ${
          ops(p.hz)
        } ${pct(p.rme)} | ${time(p.mean)} | ${ratio(r)} |`,
      );
    }
  }
  lines.push("");
  return lines.join("\n");
}
