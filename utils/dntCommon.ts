import { emptyDir } from "@deno/dnt";
import { copySync, existsSync } from "@std/fs";

export async function beforeBuild(name: string): Promise<void> {
  // Clean up dist
  await emptyDir(`../../npm/packages/${name}`);
  await emptyDir(`../../npm/samples/${name}`);
  await emptyDir(`../../npm/test/${name}/runtimes/browsers`);
  await emptyDir(`../../npm/test/${name}/runtimes/cloudflare`);
  if (existsSync("test/runtimes/fastly")) {
    await emptyDir(`../../npm/test/${name}/runtimes/fastly`);
  }

  // Remove node_modules
  try {
    await Deno.remove("test/runtimes/browsers/node_modules", {
      recursive: true,
    });
  } catch {
    // ignore
  }
  try {
    await Deno.remove("test/runtimes/bun/node_modules", {
      recursive: true,
    });
  } catch {
    // ignore
  }
  try {
    await Deno.remove("test/runtimes/browsers/node_modules", {
      recursive: true,
    });
  } catch {
    // ignore
  }
  try {
    await Deno.remove("test/runtimes/cloudflare/node_modules", {
      recursive: true,
    });
  } catch {
    // ignore
  }
  if (existsSync("test/runtimes/fastly")) {
    try {
      await Deno.remove("test/runtimes/fastly/node_modules", {
        recursive: true,
      });
    } catch {
      // ignore
    }
  }
  return;
}

export function afterBuild(name: string) {
  copySync(
    "samples/node",
    `../../npm/samples/${name}`,
    { overwrite: true },
  );
  copySync(
    "test/runtimes/browsers",
    `../../npm/test/${name}/runtimes/browsers`,
    { overwrite: true },
  );
  copySync(
    "test/runtimes/cloudflare",
    `../../npm/test/${name}/runtimes/cloudflare`,
    { overwrite: true },
  );
  if (existsSync("test/runtimes/fastly")) {
    copySync(
      "test/runtimes/fastly",
      `../../npm/test/${name}/runtimes/fastly`,
      { overwrite: true },
    );
  }
  Deno.copyFileSync("LICENSE", `../../npm/packages/${name}/LICENSE`);
  Deno.copyFileSync("README.md", `../../npm/packages/${name}/README.md`);
  writeNpmIgnore(`../../npm/packages/${name}/.npmignore`);
}

export function writeNpmIgnore(path: string) {
  Deno.writeTextFileSync(
    path,
    [
      "/src/",
      "/esm/test/",
      "/script/test/",
      "/esm/deps/",
      "/script/deps/",
      "/esm/_dnt.test_shims.*",
      "/script/_dnt.test_shims.*",
      "/test_runner.js",
      "yarn.lock",
      "pnpm-lock.yaml",
      "",
    ].join("\n"),
  );
}
