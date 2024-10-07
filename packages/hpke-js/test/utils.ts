import { dirname, fromFileUrl, join } from "@std/path";

import { isNode } from "@hpke/common";

export function getPath(name: string): string {
  const currentPath = dirname(fromFileUrl(import.meta.url));
  if (isNode()) {
    return join(currentPath, "../../", name);
  }
  return join(currentPath, name);
}
