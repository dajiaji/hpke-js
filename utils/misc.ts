export async function removeNodeModules() {
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
