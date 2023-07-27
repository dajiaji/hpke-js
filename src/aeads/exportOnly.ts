import type { AeadEncryptionContext } from "../interfaces/aeadEncryptionContext.ts";
import type { AeadInterface } from "../interfaces/aeadInterface.ts";

import { Algorithm } from "../algorithm.ts";
import { AeadId } from "../identifiers.ts";

import { NotSupportedError } from "../errors.ts";

export class ExportOnly extends Algorithm implements AeadInterface {
  public readonly id: AeadId = AeadId.ExportOnly;
  public readonly keySize: number = 0;
  public readonly nonceSize: number = 0;
  public readonly tagSize: number = 0;

  public createEncryptionContext(_key: ArrayBuffer): AeadEncryptionContext {
    throw new NotSupportedError(
      "createEncryptionContext() is not supported on ExportOnly",
    );
  }
}
