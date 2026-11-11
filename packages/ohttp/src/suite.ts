import type { AeadInterface, KdfInterface } from "@hpke/common";

/**
 * A KDF/AEAD pair with concrete primitive instances, used together with a
 * KEM to form an HPKE cipher suite.
 */
export interface OhttpSuite {
  /** KDF primitive instance. */
  kdf: KdfInterface;
  /** AEAD primitive instance. */
  aead: AeadInterface;
}

/**
 * Returns a KDF to be used by a single HPKE cipher suite.
 *
 * `CipherSuite` initializes the KDF it is given with its `suite_id`, which
 * the KDF keeps as mutable state. A KDF instance shared by multiple cipher
 * suites (e.g. the same `HkdfSha256` paired with different AEADs) would
 * therefore end up with the `suite_id` of the suite created last.
 *
 * The returned object inherits everything from `kdf` through its prototype
 * chain, while state assigned afterwards (such as the `suite_id`) is stored
 * on the returned object itself. The given instance is never modified.
 */
export function bindKdf(kdf: KdfInterface): KdfInterface {
  return Object.create(kdf);
}
