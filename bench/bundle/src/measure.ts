import { brotliCompressSync, constants, gzipSync } from "node:zlib";

export interface Sizes {
  /** Minified bytes. */
  min: number;
  /** gzip (level 9) bytes. */
  gzip: number;
  /** brotli (quality 11) bytes. */
  brotli: number;
}

export function measure(code: Uint8Array): Sizes {
  return {
    min: code.byteLength,
    gzip: gzipSync(code, { level: 9 }).byteLength,
    brotli: brotliCompressSync(code, {
      params: { [constants.BROTLI_PARAM_QUALITY]: 11 },
    }).byteLength,
  };
}
