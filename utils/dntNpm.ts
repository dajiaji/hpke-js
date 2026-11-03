#!/usr/bin/env -S deno run --allow-run
// A packageManager wrapper for dnt.
//
// Runs npm with `--workspaces=false` so that npm does not resolve the
// parent workspace (npm/package.json).

const npm = Deno.build.os === "windows" ? "npm.cmd" : "npm";

const { code } = await new Deno.Command(npm, {
  args: [...Deno.args, "--workspaces=false"],
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
}).output();

Deno.exit(code);
