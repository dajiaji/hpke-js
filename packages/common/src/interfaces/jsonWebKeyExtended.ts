/**
 * Extended JsonWebKey interface to support `pub` and `priv` properties,
 * which are not supported by the current `JsonWebKey`.
 * Both of them are defined for the newly defined JSON WWb Key type AKP (Algorithm Key Pair),
 * which is used to express Public and Private Keys for use with Algorithms.
 */
export interface JsonWebKeyExtended extends JsonWebKey {
  /** The public key in base64url encoding, which is used with the 'AKP' key type. */
  pub?: string;
  /** The private key in base64url encoding, which is used with the 'AKP' key type. */
  priv?: string;
}
