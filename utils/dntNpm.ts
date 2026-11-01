#!/usr/bin/env -S deno run --allow-read --allow-write --allow-run
// A packageManager wrapper for dnt.
//
// - Runs npm with `--workspaces=false` so that npm does not resolve the
//   parent workspace (npm/package.json).
// - On `install`, temporarily points dependencies on already-built sibling
//   packages (npm/packages/*) to `file:` specifiers, so that type checking
//   uses the local builds instead of the published versions. The original
//   package.json is restored after the install.

const npm = Deno.build.os === "windows" ? "npm.cmd" : "npm";

async function runNpm(): Promise<number> {
  const { code } = await new Deno.Command(npm, {
    args: [...Deno.args, "--workspaces=false"],
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  }).output();
  return code;
}

async function findLocalPackages(): Promise<Map<string, string>> {
  const localPackages = new Map<string, string>();
  for await (const entry of Deno.readDir("..")) {
    if (!entry.isDirectory) continue;
    try {
      const sibling = JSON.parse(
        await Deno.readTextFile(`../${entry.name}/package.json`),
      );
      if (typeof sibling.name === "string") {
        localPackages.set(sibling.name, `file:../${entry.name}`);
      }
    } catch {
      // The sibling package has not been built yet.
    }
  }
  return localPackages;
}

if (Deno.args[0] !== "install") {
  Deno.exit(await runNpm());
}

const packageJsonPath = "package.json";
const originalPackageJson = await Deno.readTextFile(packageJsonPath);
const packageJson = JSON.parse(originalPackageJson);
const localPackages = await findLocalPackages();

for (const section of ["dependencies", "devDependencies"]) {
  const deps: Record<string, string> | undefined = packageJson[section];
  if (deps === undefined) continue;
  for (const name of Object.keys(deps)) {
    const localSpecifier = localPackages.get(name);
    if (localSpecifier !== undefined) {
      deps[name] = localSpecifier;
    }
  }
}

await Deno.writeTextFile(
  packageJsonPath,
  JSON.stringify(packageJson, null, 2) + "\n",
);

let code = 1;
try {
  code = await runNpm();
} finally {
  await Deno.writeTextFile(packageJsonPath, originalPackageJson);
  try {
    // The lockfile records the temporary `file:` specifiers.
    await Deno.remove("package-lock.json");
  } catch {
    // npm may not have created a lockfile.
  }
}

Deno.exit(code);
