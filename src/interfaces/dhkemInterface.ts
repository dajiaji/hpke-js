import type { KdfInterface } from "./kdfInterface.ts";
import type { KemInterface } from "./kemInterface.ts";

/**
 * The DHKEM interface.
 */
export interface DhkemInterface extends KemInterface {
  readonly kdf: KdfInterface;
}
