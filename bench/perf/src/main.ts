/**
 * Performance benchmark for `@hpke/core` + extension packages.
 *
 * For each HPKE cipher suite (the same set as bench/bundle), an adapter for
 * `@hpke/core` + extensions (repository sources) and for panva/hpke (npm:
 * hpke, plus @panva/hpke-noble where needed) is bundled with esbuild and
 * loaded into Node.js. The adapters are checked for interoperability by
 * sealing with each library and opening with each library, then key
 * generation, single-shot seal / open and context seal are timed.
 */

import { execFileSync } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { cpus } from "node:os";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { OPS, prepare, sample, stats, warmup } from "./bench.ts";
import type { Fixture, Op } from "./bench.ts";
import { BUILD_DESCRIPTION, bundle } from "./build.ts";
import { LIBS } from "./libs.ts";
import type { Adapter, LibId } from "./libs.ts";
import { DIST, REPO_ROOT, TOOL_ROOT } from "./paths.ts";
import { printTable, toMarkdown } from "./report.ts";
import type { Meta, Result } from "./report.ts";
import { SUITES } from "./suites.ts";
import type { Suite } from "./suites.ts";

const USAGE = `Usage: node src/main.ts [options]

Options:
  --filter <substr>   Only run suites whose id contains <substr>
  --op <op>           Only run the given operation; repeatable
                      (${OPS.join(" | ")})
  --time <ms>         Measurement time per library and operation (default: 1000)
  --warmup <ms>       Warm-up time per library and operation (default: 300)
  --rounds <n>        Split the measurement into <n> rounds, alternating the
                      library order between rounds (default: 4)
  --payload <bytes>   Plaintext length (default: 64)
  --json <path>       Write the results as JSON
  --md <path>         Write the results as Markdown tables
  --keep              Keep the generated bundles under ./dist
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

function integer(name: string, value: string, min: number): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min) {
    throw new Error(`--${name} must be an integer >= ${min}: ${value}`);
  }
  return n;
}

async function loadAdapters(suite: Suite): Promise<Record<LibId, Adapter>> {
  const adapters = {} as Record<LibId, Adapter>;
  for (const lib of LIBS) {
    const file = join(
      DIST,
      `${suite.id}.${lib.id.replace(/[@/]/g, "")}.mjs`,
    );
    await writeFile(file, await bundle(lib.entry(suite)));
    adapters[lib.id] = (await import(pathToFileURL(file).href)) as Adapter;
  }
  return adapters;
}

/**
 * Generates the recipient key pair with each library in turn and checks that
 * every library can open what every library sealed. Returns the fixture
 * built from the panva/hpke key pair.
 */
async function verify(
  suite: Suite,
  adapters: Record<LibId, Adapter>,
  payload: number,
): Promise<Fixture> {
  let fixture: Fixture | undefined;
  for (const keyLib of LIBS) {
    const kp = await adapters[keyLib.id].generateKeyPair();
    const f: Fixture = {
      pkR: await adapters[keyLib.id].serializePublicKey(kp.publicKey),
      skR: await adapters[keyLib.id].serializePrivateKey(kp.privateKey),
      pt: crypto.getRandomValues(new Uint8Array(payload)),
      aad: crypto.getRandomValues(new Uint8Array(16)),
    };
    for (const sender of LIBS) {
      const s = adapters[sender.id];
      const { enc, ct } = await s.seal(
        await s.deserializePublicKey(f.pkR),
        f.pt,
        f.aad,
      );
      for (const recipient of LIBS) {
        const r = adapters[recipient.id];
        const got = await r.open(
          await r.deserializePrivateKey(f.skR),
          enc,
          ct,
          f.aad,
        );
        if (Buffer.compare(got, f.pt) !== 0) {
          throw new Error(
            `${suite.id}: keys by ${keyLib.id}, ${sender.id} -> ${recipient.id}: plaintext mismatch`,
          );
        }
      }
    }
    fixture = f;
  }
  return fixture!;
}

async function main(): Promise<void> {
  const { values: opts } = parseArgs({
    options: {
      filter: { type: "string", default: "" },
      op: { type: "string", multiple: true },
      time: { type: "string", default: "1000" },
      warmup: { type: "string", default: "300" },
      rounds: { type: "string", default: "4" },
      payload: { type: "string", default: "64" },
      json: { type: "string" },
      md: { type: "string" },
      keep: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
    strict: true,
  });
  if (opts.help) {
    process.stdout.write(USAGE);
    return;
  }

  const suites = SUITES.filter((s) => s.id.includes(opts.filter));
  if (suites.length === 0) {
    throw new Error(`No suite matches --filter ${opts.filter}`);
  }
  const opList: readonly Op[] = opts.op === undefined
    ? OPS
    : opts.op.map((op) => {
      if (!(OPS as readonly string[]).includes(op)) {
        throw new Error(`Unknown operation: ${op}`);
      }
      return op as Op;
    });
  const time = integer("time", opts.time, 1);
  const warmupMs = integer("warmup", opts.warmup, 0);
  const rounds = integer("rounds", opts.rounds, 1);
  const payload = integer("payload", opts.payload, 0);

  await rm(DIST, { recursive: true, force: true });
  await mkdir(DIST, { recursive: true });

  const results: Result[] = [];
  try {
    for (const suite of suites) {
      const adapters = await loadAdapters(suite);
      const fixture = await verify(suite, adapters, payload);
      process.stderr.write(`  ✔ ${suite.id} (verified)\n`);
      const packages = Object.fromEntries(
        LIBS.map((lib) => [lib.id, lib.packages(suite)]),
      ) as Record<LibId, string[]>;

      for (const op of opList) {
        const tasks = await Promise.all(
          LIBS.map((lib) => prepare(adapters[lib.id], op, fixture)),
        );
        for (const task of tasks) await warmup(task, warmupMs);
        const samples: number[][] = LIBS.map(() => []);
        for (let round = 0; round < rounds; round++) {
          const order = LIBS.map((_, i) => i);
          if (round % 2 === 1) order.reverse();
          for (const i of order) {
            // Append one by one: spreading a round's samples into push()
            // overflows the call stack for fast operations and long rounds.
            for (const ms of await sample(tasks[i], time / rounds)) {
              samples[i].push(ms);
            }
          }
        }
        const result: Result = {
          id: suite.id,
          label: suite.label,
          op,
          packages,
          stats: Object.fromEntries(
            LIBS.map((lib, i) => [lib.id, stats(samples[i])]),
          ) as Result["stats"],
        };
        results.push(result);
        const a = result.stats["@hpke"].hz;
        const p = result.stats["panva/hpke"].hz;
        process.stderr.write(
          `    ${op.padEnd(8)} @hpke ${a.toFixed(0).padStart(8)} ops/s  panva ${
            p.toFixed(0).padStart(8)
          } ops/s  ratio ${(a / p).toFixed(2)}\n`,
        );
      }
    }
  } finally {
    if (!opts.keep) {
      await rm(DIST, { recursive: true, force: true });
    }
  }

  const meta: Meta = {
    revision: gitRevision(),
    build: BUILD_DESCRIPTION,
    panvaVersion: await packageVersion("hpke"),
    panvaNobleVersion: await packageVersion("@panva/hpke-noble"),
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    cpu: cpus()[0]?.model.trim() ?? "unknown",
    time,
    warmup: warmupMs,
    rounds,
    payload,
  };

  printTable(results, opList);

  if (opts.json !== undefined) {
    await writeFile(
      resolve(opts.json),
      JSON.stringify({ meta, results }, null, 2) + "\n",
    );
  }
  if (opts.md !== undefined) {
    await writeFile(resolve(opts.md), toMarkdown(results, meta, opList));
  }
}

await main();
