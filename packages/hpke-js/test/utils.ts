import { dirname, fromFileUrl, join } from "@std/path";

// deno-lint-ignore no-explicit-any
export const isNode = () => (globalThis as any).process?.versions?.node != null;

export function getPath(name: string): string {
  const currentPath = dirname(fromFileUrl(import.meta.url));
  if (isNode()) {
    return join(currentPath, "../../", name);
  }
  return join(currentPath, name);
}
