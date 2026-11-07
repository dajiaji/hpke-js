import type { KemInterface } from "@hpke/common";
import { NotSupportedError } from "@hpke/common";

/**
 * Reject authentication for KEMs that explicitly declare it unsupported.
 * KEMs without an auth property retain their existing behavior.
 * @internal
 */
export function checkAuthSupport(kem: KemInterface): void {
  if ("auth" in kem && kem.auth === false) {
    throw new NotSupportedError(
      "Auth and AuthPSK modes are not supported by this KEM",
    );
  }
}
