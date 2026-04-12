import { execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

let server: ChildProcess | undefined;
let fastlyHome: string | undefined;
let stdoutLog = "";
let stderrLog = "";

const fastlyCmd = process.platform === "win32" ? "fastly.cmd" : "fastly";

async function getAvailablePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (addr === null || typeof addr === "string") {
        srv.close(() => reject(new Error("Failed to allocate a TCP port")));
        return;
      }
      const { port } = addr;
      srv.close((err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(port);
      });
    });
    srv.on("error", reject);
  });
}

function createFastlyEnv(): NodeJS.ProcessEnv {
  fastlyHome = mkdtempSync(join(tmpdir(), "hpke-fastly-"));
  return {
    ...process.env,
    HOME: fastlyHome,
    XDG_CONFIG_HOME: join(fastlyHome, ".config"),
    XDG_CACHE_HOME: join(fastlyHome, ".cache"),
  };
}

function resolveFastlyBin(): string {
  const candidates = [
    join(import.meta.dirname, "node_modules", ".bin", fastlyCmd),
    resolve(import.meta.dirname, "../../../../node_modules/.bin", fastlyCmd),
  ];
  const bin = candidates.find((candidate) => existsSync(candidate));
  if (bin === undefined) {
    throw new Error(
      "Fastly CLI is not installed. Run npm install in this workspace to install the local devDependency.",
    );
  }
  return bin;
}

async function waitForServer(
  url: string,
  child: ChildProcess,
  timeout = 60000,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (child.exitCode !== null) {
      throw new Error(
        `Fastly server exited before readiness check completed (code=${child.exitCode}).\nstdout:\n${stdoutLog}\nstderr:\n${stderrLog}`,
      );
    }
    try {
      const res = await fetch(url);
      if (res.status === 200) {
        return;
      }
    } catch {
      // ignore while waiting for Viceroy to accept requests
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(
    `Server did not start within ${timeout}ms.\nstdout:\n${stdoutLog}\nstderr:\n${stderrLog}`,
  );
}

export async function setup() {
  const env = createFastlyEnv();
  const fastlyBin = resolveFastlyBin();
  const port = await getAvailablePort();
  const addr = `127.0.0.1:${port}`;
  const readinessUrl = `http://${addr}/test?kem=0x0010&kdf=0x0001&aead=0x0001`;
  stdoutLog = "";
  stderrLog = "";
  process.env.FASTLY_TEST_ORIGIN = `http://${addr}`;

  // Check if the workspace-local Fastly CLI is installed.
  try {
    execFileSync(fastlyBin, ["version"], {
      cwd: import.meta.dirname,
      env,
      stdio: "pipe",
    });
  } catch (e: unknown) {
    throw new Error(
      "Failed to start the workspace-local Fastly CLI: " +
        (e instanceof Error ? e.message : String(e)),
    );
  }

  // Start Fastly local server (Viceroy).
  // `fastly compute serve` builds the app and then starts serving.
  server = spawn(fastlyBin, ["compute", "serve", "--addr", addr], {
    cwd: import.meta.dirname,
    env,
    stdio: "pipe",
  });

  server.stdout?.setEncoding("utf8");
  server.stdout?.on("data", (chunk: string) => {
    stdoutLog += chunk;
  });
  server.stderr?.setEncoding("utf8");
  server.stderr?.on("data", (chunk: string) => {
    stderrLog += chunk;
  });

  server.on("error", (err: Error) => {
    console.error("Failed to start Fastly local server:", err.message);
  });

  // Wait for the server to be ready (includes build time).
  // Viceroy listens on 127.0.0.1:7676 by default.
  await waitForServer(readinessUrl, server);
}

export async function teardown() {
  if (server) {
    server.stdout?.destroy();
    server.stderr?.destroy();
    const exited = new Promise<void>((resolve) => {
      server?.once("exit", () => resolve());
    });
    server.kill("SIGTERM");
    await Promise.race([
      exited,
      new Promise((resolve) => setTimeout(resolve, 3000)),
    ]);
    if (server.exitCode === null) {
      server.kill("SIGKILL");
    }
    server = undefined;
  }
  if (fastlyHome) {
    rmSync(fastlyHome, { recursive: true, force: true });
    fastlyHome = undefined;
  }
  delete process.env.FASTLY_TEST_ORIGIN;
  stdoutLog = "";
  stderrLog = "";
}
