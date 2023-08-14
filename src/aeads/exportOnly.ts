import type { AeadEncryptionContext } from "../interfaces/aeadEncryptionContext.ts";
import type { AeadInterface } from "../interfaces/aeadInterface.ts";

import { AeadId } from "../identifiers.ts";

import { NotSupportedError } from "../errors.ts";

export class ExportOnly implements AeadInterface {
  public readonly id: AeadId = AeadId.ExportOnly;
  public readonly keySize: number = 0;
  public readonly nonceSize: number = 0;
  public readonly tagSize: number = 0;

  public createEncryptionContext(_key: ArrayBuffer): AeadEncryptionContext {
    throw new NotSupportedError("Export only");
  }
}
