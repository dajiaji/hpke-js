import { NotSupportedError } from "@hpke/common";

export function emitNotSupported<T>(): Promise<T> {
  return new Promise((_resolve, reject) => {
    reject(new NotSupportedError("Not supported"));
  });
}
