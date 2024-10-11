import { dirname, fromFileUrl, join } from "@std/path";

import { isDeno } from "@hpke/common";

export function getPath(name: string): string {
  const currentPath = dirname(fromFileUrl(import.meta.url));
  if (isDeno()) {
    return join(currentPath, name);
  }
  return join(currentPath, "../../", name);
}
