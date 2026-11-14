import type {
  AeadInterface,
  KdfInterface,
  KemInterface,
  KeyScheduleParams,
} from "@hpke/common";

import {
  concat,
  EMPTY,
  i2Osp,
  INFO_LENGTH_LIMIT,
  INPUT_LENGTH_LIMIT,
  InvalidParamError,
  MINIMUM_PSK_LENGTH,
  NotSupportedError,
  toUint8Array,
} from "@hpke/common";

import type { AeadParams } from "./interfaces/aeadParams.ts";
import type { CipherSuiteParams } from "./interfaces/cipherSuiteParams.ts";

// This module holds the logic shared by senders and recipients. Anything
// specific to one of them belongs to senderContext.ts or recipientContext.ts
// so that bundlers can drop the unused side.

/**
 * An initialized ciphersuite, that is, the algorithms whose KDF has been
 * bound to the suite_id by {@link initSuite}.
 */
export interface Suite {
  readonly kem: KemInterface;
  readonly kdf: KdfInterface;
  readonly aead: AeadInterface;
}

// psk_id_hash for the empty psk_id (i.e., the Base and Auth modes), which is a
// constant for each suite. Module-scoped so that it is not reachable from the
// outside.
const EMPTY_PSK_ID_HASHES = /* @__PURE__ */ new WeakMap<Suite, ArrayBuffer>();

// b"base_nonce"
// deno-fmt-ignore
const LABEL_BASE_NONCE = /* @__PURE__ */ new Uint8Array([
  98, 97, 115, 101, 95, 110, 111, 110, 99, 101,
]);
// b"exp"
const LABEL_EXP = /* @__PURE__ */ new Uint8Array([101, 120, 112]);
// b"info_hash"
// deno-fmt-ignore
const LABEL_INFO_HASH = /* @__PURE__ */ new Uint8Array([
  105, 110, 102, 111, 95, 104, 97, 115, 104,
]);
// b"key"
const LABEL_KEY = /* @__PURE__ */ new Uint8Array([107, 101, 121]);
// b"psk_id_hash"
// deno-fmt-ignore
const LABEL_PSK_ID_HASH = /* @__PURE__ */ new Uint8Array([
  112, 115, 107, 95, 105, 100, 95, 104, 97, 115, 104,
]);
// b"secret"
const LABEL_SECRET = /* @__PURE__ */ new Uint8Array([
  115,
  101,
  99,
  114,
  101,
  116,
]);
// b"HPKE"
// deno-fmt-ignore
const SUITE_ID_HEADER_HPKE = /* @__PURE__ */ new Uint8Array([
  72, 80, 75, 69, 0, 0, 0, 0, 0, 0,
]);

/**
 * Validates the ciphersuite parameters and binds the KDF to the suite_id.
 *
 * @throws {@link InvalidParamError}
 */
export function initSuite(params: CipherSuiteParams): Suite {
  if (typeof params.kem === "number") {
    throw new InvalidParamError("KemId cannot be used");
  }
  if (typeof params.kdf === "number") {
    throw new InvalidParamError("KdfId cannot be used");
  }
  if (typeof params.aead === "number") {
    throw new InvalidParamError("AeadId cannot be used");
  }
  const suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
  suiteId.set(i2Osp(params.kem.id, 2), 4);
  suiteId.set(i2Osp(params.kdf.id, 2), 6);
  suiteId.set(i2Osp(params.aead.id, 2), 8);
  params.kdf.init(suiteId);
  return params as Suite;
}

/**
 * Validates the inputs of the key schedule.
 *
 * @param auth Whether the Auth or AuthPSK mode is requested.
 * @throws {@link NotSupportedError} if the KEM does not support authentication.
 * @throws {@link InvalidParamError}
 */
export function checkParams(
  kem: KemInterface,
  params: KeyScheduleParams,
  auth: boolean,
): void {
  // Reject authentication for KEMs that explicitly declare it unsupported.
  // KEMs without an auth property retain their existing behavior.
  if (auth && "auth" in kem && kem.auth === false) {
    throw new NotSupportedError(
      "Auth and AuthPSK modes are not supported by this KEM",
    );
  }
  if (
    params.info !== undefined &&
    params.info.byteLength > INFO_LENGTH_LIMIT
  ) {
    throw new InvalidParamError("Too long info");
  }
  if (params.psk !== undefined) {
    if (params.psk.key.byteLength < MINIMUM_PSK_LENGTH) {
      throw new InvalidParamError(
        `PSK must have at least ${MINIMUM_PSK_LENGTH} bytes`,
      );
    }
    if (params.psk.key.byteLength > INPUT_LENGTH_LIMIT) {
      throw new InvalidParamError("Too long psk.key");
    }
    if (params.psk.id.byteLength > INPUT_LENGTH_LIMIT) {
      throw new InvalidParamError("Too long psk.id");
    }
  }
}

/**
 * Runs the key schedule defined in
 * [RFC9180 Section 5.1](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1).
 *
 * @param auth Whether the Auth or AuthPSK mode is requested.
 */
export async function keySchedule(
  suite: Suite,
  params: KeyScheduleParams,
  sharedSecret: ArrayBuffer,
  auth: boolean,
): Promise<AeadParams> {
  const { kdf, aead } = suite;

  // Mode: Base (0x00), Psk (0x01), Auth (0x02) or AuthPsk (0x03).
  //
  // There is no need to verify the PSK inputs against the mode because this
  // library does not allow users to explicitly specify the mode.
  const mode = (params.psk !== undefined ? 1 : 0) | (auth ? 2 : 0);

  const pskId = params.psk === undefined ? EMPTY : toUint8Array(params.psk.id);
  const info = params.info === undefined ? EMPTY : toUint8Array(params.info);
  const noPskId = pskId.byteLength === 0;
  const [pskIdHash, infoHash] = await Promise.all([
    (noPskId && EMPTY_PSK_ID_HASHES.get(suite)) ||
    kdf.labeledExtract(EMPTY, LABEL_PSK_ID_HASH, pskId),
    kdf.labeledExtract(EMPTY, LABEL_INFO_HASH, info),
  ]);
  if (noPskId) {
    EMPTY_PSK_ID_HASHES.set(suite, pskIdHash);
  }

  const keyScheduleContext = concat(
    new Uint8Array([mode]),
    new Uint8Array(pskIdHash),
    new Uint8Array(infoHash),
  );

  const psk = params.psk === undefined ? EMPTY : toUint8Array(params.psk.key);
  const ikm = kdf.buildLabeledIkm(LABEL_SECRET, psk);

  // exporter_secret, key and base_nonce are derived concurrently.
  const exportOnly = aead.id === 0xffff; /* AeadId.ExportOnly */
  const [exporterSecret, key, baseNonce] = await Promise.all(
    (
      [
        [LABEL_EXP, kdf.hashSize],
        [LABEL_KEY, aead.keySize],
        [LABEL_BASE_NONCE, aead.nonceSize],
      ] as const
    ).slice(0, exportOnly ? 1 : 3).map(([label, len]) =>
      kdf.extractAndExpand(
        sharedSecret,
        ikm,
        kdf.buildLabeledInfo(label, keyScheduleContext, len),
        len,
      )
    ),
  );

  // For ExportOnly, key and baseNonce are undefined.
  return {
    aead: aead,
    exporterSecret: exporterSecret,
    key: key,
    baseNonce: baseNonce && new Uint8Array(baseNonce),
    seq: 0,
  };
}
