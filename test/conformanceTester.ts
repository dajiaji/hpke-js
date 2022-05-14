import type { PreSharedKey } from '../src/interfaces/preSharedKey';
import type { TestVector } from './testVector';

import { CipherSuite } from '../src/cipherSuite';
import { WebCrypto } from '../src/webCrypto';
import { loadSubtleCrypto } from '../src/webCrypto';
import {
  hexStringToBytes,
  bytesToBase64Url,
  kemToKeyGenAlgorithm,
} from './utils';

export class ConformanceTester extends WebCrypto {

  private _count = 0;

  public count(): number {
    return this._count;
  }

  public async test(v: TestVector) {

    // console.log(v.mode, "/", v.kem_id, "/", v.kdf_id, "/", v.aead_id);

    const info = hexStringToBytes(v.info);
    const ikmE = hexStringToBytes(v.ikmE);
    const pkEm = hexStringToBytes(v.pkEm);
    const skEm = hexStringToBytes(v.skEm);
    let psk: PreSharedKey | undefined = undefined;
    if (v.psk !== undefined && v.psk_id !== undefined) {
      psk = { id: new ArrayBuffer(0), key: new ArrayBuffer(0) };
      psk.key = hexStringToBytes(v.psk);
      psk.id = hexStringToBytes(v.psk_id);
    }
    const ikmR = hexStringToBytes(v.ikmR);
    const pkRm = hexStringToBytes(v.pkRm);
    const skRm = hexStringToBytes(v.skRm);
    let skp: CryptoKeyPair | undefined = undefined;
    let pks: CryptoKey | undefined = undefined;
    if (v.skSm !== undefined && v.pkSm !== undefined) {
      const skSm = hexStringToBytes(v.skSm);
      const pkSm = hexStringToBytes(v.pkSm);
      skp = await this.bytesToCryptoKeyPair(skSm, pkSm, kemToKeyGenAlgorithm(v.kem_id));
      pks = skp.publicKey;
    }
    const enc = hexStringToBytes(v.enc);

    const rkp = await this.bytesToCryptoKeyPair(skRm, pkRm, kemToKeyGenAlgorithm(v.kem_id));
    const ekp = await this.bytesToCryptoKeyPair(skEm, pkEm, kemToKeyGenAlgorithm(v.kem_id));

    const suite = new CipherSuite({ kem: v.kem_id, kdf: v.kdf_id, aead: v.aead_id });

    // deriveKeyPair
    const derivedR = await suite.deriveKeyPair(ikmR.buffer);
    const derivedPkRm = await this._api.exportKey('raw', derivedR.publicKey);
    expect(new Uint8Array(derivedPkRm)).toEqual(pkRm);
    const derivedE = await suite.deriveKeyPair(ikmE.buffer);
    const derivedPkEm = await this._api.exportKey('raw', derivedE.publicKey);
    expect(new Uint8Array(derivedPkEm)).toEqual(pkEm);

    const sender = await suite.createSenderContext({
      info: info,
      psk: psk,
      recipientPublicKey: rkp.publicKey,
      senderKey: skp,
      nonEphemeralKeyPair: ekp, // FOR DEBUGGING/TESTING PURPOSES ONLY.
    });
    expect(new Uint8Array(sender.enc)).toEqual(enc);

    const recipient = await suite.createRecipientContext({
      info: info,
      psk: psk,
      recipientKey: rkp,
      enc: sender.enc,
      senderPublicKey: pks,
    });

    // encryption
    if (v.aead_id !== 0xFFFF) {
      for (const ve of v.encryptions) {
        const pt = hexStringToBytes(ve.pt);
        const aad = hexStringToBytes(ve.aad);
        const ct = hexStringToBytes(ve.ct);

        const sealed = await sender.seal(pt, aad);
        const opened = await recipient.open(sealed, aad);
        expect(new Uint8Array(sealed)).toEqual(ct);
        expect(new Uint8Array(opened)).toEqual(pt);
      }
    }

    // export
    for (const ve of v.exports) {
      const ec = ve.exporter_context.length === 0 ? new ArrayBuffer(0) : hexStringToBytes(ve.exporter_context);
      const ev = hexStringToBytes(ve.exported_value);

      let exported = await sender.export(ec, ve.L);
      expect(new Uint8Array(exported)).toEqual(ev);
      exported = await recipient.export(ec, ve.L);
      expect(new Uint8Array(exported)).toEqual(ev);
    }
    this._count++;
  }

  private async bytesToCryptoKeyPair(skm: Uint8Array, pkm: Uint8Array, alg: EcKeyGenParams): Promise<CryptoKeyPair> {
    const pk = await this._api.importKey('raw', pkm, alg, true, ['deriveKey', 'deriveBits']);
    const jwk = await this._api.exportKey('jwk', pk);
    jwk['d'] = bytesToBase64Url(skm);
    const sk = await this._api.importKey('jwk', jwk, alg, true, ['deriveKey', 'deriveBits']);
    return { privateKey: sk, publicKey: pk };
  }
}

export async function createConformanceTester(): Promise<ConformanceTester> {
  const api = await loadSubtleCrypto();
  return new ConformanceTester(api);
}
