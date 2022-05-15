import type { AeadParams } from './interfaces/aeadParams';
import type { CipherSuiteParams } from './interfaces/cipherSuiteParams';
import type { KeyScheduleParams } from './interfaces/keyScheduleParams';

import { Aead, Kdf, Mode } from './identifiers';
import { KdfCommon } from './kdfCommon';
import { i2Osp } from './utils/misc';

import * as consts from './consts';
import * as errors from './errors';

export class KdfContext extends KdfCommon {

  private _aead: Aead;
  private _nK: number;
  private _nN: number;
  private _nT: number;

  constructor(api: SubtleCrypto, params: CipherSuiteParams) {
    const suiteId = new Uint8Array(10);
    suiteId.set(consts.SUITE_ID_HEADER_HPKE, 0);
    suiteId.set(i2Osp(params.kem, 2), 4);
    suiteId.set(i2Osp(params.kdf, 2), 6);
    suiteId.set(i2Osp(params.aead, 2), 8);

    let algHash: HmacKeyGenParams;
    switch (params.kdf) {
      case Kdf.HkdfSha256:
        algHash = { name: 'HMAC', hash: 'SHA-256', length: 256 };
        break;
      case Kdf.HkdfSha384:
        algHash = { name: 'HMAC', hash: 'SHA-384', length: 384 };
        break;
      default:
        // case Kdf.HkdfSha512:
        algHash = { name: 'HMAC', hash: 'SHA-512', length: 512 };
        break;
    }
    super(api, suiteId, algHash);

    this._aead = params.aead;
    switch (this._aead) {
      case Aead.Aes128Gcm:
        this._nK = 16;
        this._nN = 12;
        this._nT = 16;
        break;
      case Aead.Aes256Gcm:
        this._nK = 32;
        this._nN = 12;
        this._nT = 16;
        break;
      default:
        // case Aead.ExportOnly:
        this._nK = 0;
        this._nN = 0;
        this._nT = 0;
        break;
    }
    return;
  }

  // private verifyPskInputs(mode: Mode, params: KeyScheduleParams) {
  //   const gotPsk = (params.psk !== undefined);
  //   const gotPskId = (params.psk !== undefined && params.psk.id.byteLength > 0);
  //   if (gotPsk !== gotPskId) {
  //     throw new Error('Inconsistent PSK inputs');
  //   }
  //   if (gotPsk && (mode === Mode.Base || mode === Mode.Auth)) {
  //     throw new Error('PSK input provided when not needed');
  //   }
  //   if (!gotPsk && (mode === Mode.Psk || mode === Mode.AuthPsk)) {
  //     throw new Error('Missing required PSK input');
  //   }
  //   return;
  // }

  public async keySchedule(mode: Mode, sharedSecret: ArrayBuffer, params: KeyScheduleParams): Promise<AeadParams> {

    // Currently, there is no point in executing this function
    // because this hpke library does not allow users to explicitly specify the mode.
    //
    // this.verifyPskInputs(mode, params);

    const pskId = params.psk === undefined ? consts.EMPTY : new Uint8Array(params.psk.id);
    const pskIdHash = await this.labeledExtract(consts.EMPTY, consts.LABEL_PSK_ID_HASH, pskId);

    const info = params.info === undefined ? consts.EMPTY : new Uint8Array(params.info);
    const infoHash = await this.labeledExtract(consts.EMPTY, consts.LABEL_INFO_HASH, info);

    const keyScheduleContext = new Uint8Array(1 + pskIdHash.byteLength + infoHash.byteLength);
    keyScheduleContext.set(new Uint8Array([mode]), 0);
    keyScheduleContext.set(new Uint8Array(pskIdHash), 1);
    keyScheduleContext.set(new Uint8Array(infoHash), 1 + pskIdHash.byteLength);

    const psk = params.psk === undefined ? consts.EMPTY : new Uint8Array(params.psk.key);
    const ikm = this.buildLabeledIkm(consts.LABEL_SECRET, psk);

    const exporterSecretInfo = this.buildLabeledInfo(consts.LABEL_EXP, keyScheduleContext, this._nH);
    const exporterSecret = await this.extractAndExpand(sharedSecret, ikm, exporterSecretInfo, this._nH);

    if (this._aead === Aead.ExportOnly) {
      return {
        aead: this._aead,
        nK: this._nK,
        nN: this._nN,
        nT: this._nT,
        exporterSecret: exporterSecret,
      };
    }

    const keyInfo = this.buildLabeledInfo(consts.LABEL_KEY, keyScheduleContext, this._nK);
    const key = await this.extractAndExpand(sharedSecret, ikm, keyInfo, this._nK);

    const baseNonceInfo = this.buildLabeledInfo(consts.LABEL_BASE_NONCE, keyScheduleContext, this._nN);
    const baseNonce = await this.extractAndExpand(sharedSecret, ikm, baseNonceInfo, this._nN);

    return {
      aead: this._aead,
      nK: this._nK,
      nN: this._nN,
      nT: this._nT,
      exporterSecret: exporterSecret,
      key: key,
      baseNonce: new Uint8Array(baseNonce),
      seq: 0,
    };
  }
}
