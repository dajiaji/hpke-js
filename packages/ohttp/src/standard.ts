import type { OhttpEncoding } from "./encoding.ts";
import { collect, fragments, stream } from "./streams.ts";
import {
  decapsulateRequest,
  decapsulateResponse,
  encapsulateRequest,
  encapsulateResponse,
} from "./encapsulation.ts";
import { OhttpError } from "./errors.ts";

/** RFC 9458 encoding. Whole messages are buffered for authentication. */
export function createStandardEncoding(): OhttpEncoding {
  const requestContentType = "message/ohttp-req";
  const responseContentType = "message/ohttp-res";
  return {
    requestContentType,
    responseContentType,
    incremental: false,
    async encapsulateRequest(suite, keyId, key, source) {
      const result = await encapsulateRequest(
        suite,
        keyId,
        suite.kem.id,
        suite.kdf.id,
        suite.aead.id,
        key,
        await collect(source),
      );
      let used = false;
      return {
        body: stream(fragments([result.encRequest])),
        contentType: requestContentType,
        async decapsulateResponse(source) {
          if (used) throw new OhttpError("Response already consumed");
          used = true;
          return stream(
            fragments([
              await decapsulateResponse(result.context, await collect(source)),
            ]),
          );
        },
      };
    },
    async decapsulateRequest(suite, keyId, key, source) {
      const result = await decapsulateRequest(
        suite,
        key,
        keyId,
        suite.kem.id,
        await collect(source),
      );
      let used = false;
      return {
        body: stream(fragments([result.binaryRequest])),
        async encapsulateResponse(source) {
          if (used) throw new OhttpError("Response already encapsulated");
          used = true;
          const data = await encapsulateResponse(
            result.context,
            await collect(source),
          );
          return {
            body: stream(fragments([data])),
            contentType: responseContentType,
          };
        },
      };
    },
  };
}
