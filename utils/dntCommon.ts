import { emptyDir } from "@deno/dnt";
import { copySync } from "@std/fs";

export async function beforeBuild(name: string): Promise<void> {
  // Clean up dist
  await emptyDir(`../../npm/packages/${name}`);
  await emptyDir(`../../npm/samples/${name}`);
  await emptyDir(`../../npm/test/${name}/runtimes/cloudflare`);

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
    await Deno.remove("test/runtimes/cloudflare/node_modules", {
      recursive: true,
    });
  } catch {
    // ignore
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
    "test/runtimes/cloudflare",
    `../../npm/test/${name}/runtimes/cloudflare`,
    { overwrite: true },
  );
  Deno.copyFileSync("LICENSE", `../../npm/packages/${name}/LICENSE`);
  Deno.copyFileSync("README.md", `../../npm/packages/${name}/README.md`);
}
