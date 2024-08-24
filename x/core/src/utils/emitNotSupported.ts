import { NotSupportedError } from "../errors.ts";

export function emitNotSupported<T>(): Promise<T> {
  return new Promise((_resolve, reject) => {
    reject(new NotSupportedError("Not supported"));
  });
}
