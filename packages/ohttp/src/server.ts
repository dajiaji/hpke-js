import { CipherSuite } from "@hpke/core";
import type { AeadInterface, KdfInterface, KemInterface } from "@hpke/common";
import { serializeKeyConfig, validateKeyId } from "./keyConfig.ts";
import type { OhttpEncoding, OhttpGatewayContext } from "./encoding.ts";
import { ByteReader, type OhttpSource, stream } from "./streams.ts";
import { bindKdf } from "./suite.ts";
import { OhttpError } from "./errors.ts";

/** A KDF/AEAD pair with concrete primitive instances. */
export interface KdfAeadPair {
  kdf: KdfInterface;
  aead: AeadInterface;
}

/** Gateway configuration with explicit keys, primitives, and wire encoding. */
export interface OhttpGatewayParams {
  keyId: number;
  kem: KemInterface;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  kdfAeadPairs: KdfAeadPair[];
  encoding: OhttpEncoding;
}

/** Binary HTTP gateway. */
export interface OhttpGateway {
  readonly publicKeyConfig: Promise<Uint8Array>;
  readonly encoding: OhttpEncoding;
  decapsulateRequest(source: OhttpSource): Promise<OhttpGatewayContext>;
}

/** Create a gateway using only the supplied primitives and encoding. */
export function createOhttpGateway(params: OhttpGatewayParams): OhttpGateway {
  validateKeyId(params.keyId);
  if (!params.kdfAeadPairs.length) {
    throw new OhttpError("At least one KDF/AEAD pair is required");
  }
  const { keyId, kem, privateKey, publicKey, encoding } = params;
  const pairs = params.kdfAeadPairs.map((p) => ({ ...p }));
  return {
    encoding,
    get publicKeyConfig() {
      return kem.serializePublicKey(publicKey).then((raw) =>
        serializeKeyConfig({
          keyId,
          kem: kem.id,
          publicKey: new Uint8Array(raw),
          cipherSuites: pairs.map((p) => ({ kdf: p.kdf.id, aead: p.aead.id })),
        })
      );
    },
    async decapsulateRequest(source) {
      const reader = new ByteReader(source);
      try {
        const header = await reader.read(7);
        const view = new DataView(header.buffer);
        const pair = pairs.find((p) =>
          p.kdf.id === view.getUint16(3) && p.aead.id === view.getUint16(5)
        );
        if (!pair) throw new OhttpError("Unsupported cipher suite");
        const suite = new CipherSuite({ kem, ...pair, kdf: bindKdf(pair.kdf) });
        const replay = (async function* () {
          try {
            yield header;
            yield* reader.rest();
          } finally {
            await reader.close();
          }
        })();
        return await encoding.decapsulateRequest(
          suite,
          keyId,
          privateKey,
          stream(replay, () => reader.close()),
        );
      } catch (error) {
        await reader.close();
        throw error;
      }
    },
  };
}
