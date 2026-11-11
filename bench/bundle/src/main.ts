/**
 * Bundle size benchmark for `@hpke/core` + extension packages.
 *
 * For each HPKE cipher suite, bundles a minimal "typical" sender and recipient
 * application with real-world bundlers (esbuild, rollup + terser) and reports
 * the minified / gzip / brotli sizes. panva/hpke (npm: hpke, plus
 * @panva/hpke-noble where needed) is measured the same way for comparison.
 * `sideEffects: false` is honored for every package on both sides.
 */

import { execFileSync } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";

import { BUNDLERS } from "./bundlers/index.ts";
import type { BundlerId } from "./bundlers/index.ts";
import { LIBS, ROLES } from "./libs.ts";
import type { LibId, Role } from "./libs.ts";
import { measure } from "./measure.ts";
import { benchmarkJose, JOSE_SUITE_ID } from "./jose.ts";
import type { JoseResult } from "./jose.ts";
import {
  benchmarkOhttp,
  normalizeOhttpBaseline,
  OHTTP_SUITES,
  reportOhttp,
} from "./ohttp.ts";
import type { OhttpBaselineResult, OhttpResult } from "./ohttp.ts";
import { DIST, REPO_ROOT, TOOL_ROOT } from "./paths.ts";
import {
  joseToMarkdown,
  printJoseTable,
  printModules,
  printTable,
  toMarkdown,
} from "./report.ts";
import type { LibResult, Meta, Result } from "./report.ts";
import { SUITES } from "./suites.ts";
import { verify } from "./verify.ts";
import type { BundleFiles } from "./verify.ts";

const USAGE = `Usage: node src/main.ts [options]

Options:
  --filter <substr>   Only run suites whose id contains <substr>
  --bundler <id>      Only use the given bundler (esbuild | rollup); repeatable
  --analyze           Print the per-module size breakdown (esbuild only)
  --json <path>       Write the results as JSON
  --md <path>         Write the results as Markdown tables
  --keep              Keep the generated bundles under ./dist
  --compare <json>    Compare OHTTP sizes with a previous results.json
  --no-verify         Skip the runtime seal/open check of the bundles
  -h, --help          Show this help
`;

function gitRevision(): string {
  try {
    const git = (...args: string[]) =>
      execFileSync("git", args, { cwd: REPO_ROOT }).toString().trim();
    const rev = git("rev-parse", "--short", "HEAD");
    // Both the measured sources and this tool (incl. its lockfile) affect
    // the results.
    const dirty = git(
      "status",
      "--porcelain",
      "--",
      "packages",
      relative(REPO_ROOT, TOOL_ROOT),
    ).length > 0;
    return dirty ? `${rev}-dirty` : rev;
  } catch {
    return "unknown";
  }
}

async function packageVersion(name: string): Promise<string> {
  const path = join(TOOL_ROOT, "node_modules", name, "package.json");
  const pkg = JSON.parse(await readFile(path, "utf8")) as { version: string };
  return pkg.version;
}

async function main(): Promise<void> {
  const { values: opts } = parseArgs({
    options: {
      filter: { type: "string", default: "" },
      bundler: { type: "string", multiple: true },
      analyze: { type: "boolean", default: false },
      json: { type: "string" },
      md: { type: "string" },
      keep: { type: "boolean", default: false },
      compare: { type: "string" },
      verify: { type: "boolean", default: true },
      help: { type: "boolean", short: "h", default: false },
    },
    allowNegative: true,
    strict: true,
  });
  if (opts.help) {
    process.stdout.write(USAGE);
    return;
  }

  const suites = SUITES.filter((s) => s.id.includes(opts.filter));
  const ohttpSuites = OHTTP_SUITES.filter((s) => s.id.includes(opts.filter));
  const runJose = JOSE_SUITE_ID.includes(opts.filter);
  if (suites.length === 0 && ohttpSuites.length === 0 && !runJose) {
    throw new Error(`No suite matches --filter ${opts.filter}`);
  }
  const bundlers = opts.bundler === undefined
    ? BUNDLERS
    : opts.bundler.map((id) => {
      const b = BUNDLERS.find((b) => b.id === id);
      if (b === undefined) throw new Error(`Unknown bundler: ${id}`);
      return b;
    });

  const baseline = opts.compare === undefined ? undefined : JSON.parse(
    await readFile(resolve(opts.compare), "utf8"),
  ) as { meta: Meta; ohttpResults?: OhttpBaselineResult[] };
  if (baseline !== undefined && !Array.isArray(baseline.ohttpResults)) {
    throw new Error("--compare requires results.json containing ohttpResults");
  }
  const ohttpBeforeResults = baseline?.ohttpResults === undefined
    ? undefined
    : normalizeOhttpBaseline(baseline.ohttpResults);
  // Bundles are always written to disk (they are imported for verification);
  // ./dist is removed afterwards unless --keep is given.
  await rm(DIST, { recursive: true, force: true });
  await mkdir(DIST, { recursive: true });

  const results: Result[] = [];
  let ohttpResults: OhttpResult[] = [];
  let joseResults: JoseResult[] = [];
  try {
    for (const suite of suites) {
      const packages = Object.fromEntries(
        LIBS.map((lib) => [lib.id, lib.packages(suite)]),
      ) as Record<LibId, string[]>;
      const byRole = Object.fromEntries(
        ROLES.map((role) => [role, {}]),
      ) as Record<Role, Result["sizes"]>;

      for (const bundler of bundlers) {
        const files = {} as BundleFiles;
        for (const role of ROLES) {
          byRole[role][bundler.id] = {} as Record<LibId, LibResult>;
        }
        for (const lib of LIBS) {
          files[lib.id] = {} as Record<Role, string>;
          for (const role of ROLES) {
            const { code, modules } = await bundler.bundle(
              lib.entry(suite, role),
            );
            const file = join(
              DIST,
              bundler.id,
              `${suite.id}.${lib.id.replace(/[@/]/g, "")}.${role}.mjs`,
            );
            await mkdir(join(DIST, bundler.id), { recursive: true });
            await writeFile(file, code);
            files[lib.id][role] = file;
            byRole[role][bundler.id]![lib.id] = { ...measure(code), modules };
            if (opts.analyze && modules !== undefined) {
              printModules(
                `${suite.id} / ${bundler.id} / ${lib.id} / ${role}`,
                modules,
              );
            }
          }
        }
        if (opts.verify) {
          await verify(suite, files);
        }
        process.stderr.write(
          `  ${opts.verify ? "✔" : "-"} ${suite.id} (${bundler.id})\n`,
        );
      }

      for (const role of ROLES) {
        results.push({
          id: suite.id,
          label: suite.label,
          role,
          packages,
          sizes: byRole[role],
        });
      }
    }
    if (runJose) {
      joseResults = await benchmarkJose(bundlers, opts.verify, opts.analyze);
    }
    ohttpResults = await benchmarkOhttp(ohttpSuites, bundlers, DIST, {
      verify: opts.verify,
      analyze: opts.analyze,
    });
  } finally {
    if (!opts.keep) {
      await rm(DIST, { recursive: true, force: true });
    }
  }

  const bundlerIds: BundlerId[] = bundlers.map((b) => b.id);
  const meta: Meta = {
    revision: gitRevision(),
    verified: opts.verify,
    bundlers: Object.fromEntries(bundlers.map((b) => [b.id, b.description])),
    panvaVersion: await packageVersion("hpke"),
    panvaNobleVersion: await packageVersion("@panva/hpke-noble"),
    node: process.version,
  };

  if (results.length) printTable(results, bundlerIds);
  if (joseResults.length) printJoseTable(joseResults, bundlerIds);
  const ohttpMarkdown = reportOhttp(
    ohttpResults,
    bundlerIds,
    ohttpBeforeResults,
  );
  const baselineMeta = baseline === undefined ? undefined : {
    path: resolve(opts.compare!),
    revision: baseline.meta.revision,
    verified: baseline.meta.verified,
  };

  if (opts.json !== undefined) {
    await writeFile(
      resolve(opts.json),
      JSON.stringify(
        {
          meta,
          results,
          joseResults,
          ohttpResults,
          ohttpBaseline: baselineMeta,
          ohttpBeforeResults,
        },
        null,
        2,
      ) + "\n",
    );
  }
  if (opts.md !== undefined) {
    const comparisonNote = baselineMeta === undefined
      ? ""
      : `\nOHTTP baseline: \`${baselineMeta.path}\` @ \`${baselineMeta.revision}\` (verified: ${baselineMeta.verified}).\n`;
    await writeFile(
      resolve(opts.md),
      toMarkdown(results, meta, bundlerIds) +
        joseToMarkdown(joseResults, meta, bundlerIds) + comparisonNote +
        ohttpMarkdown,
    );
  }
}

await main();
