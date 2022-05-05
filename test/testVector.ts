import type { Kem, Kdf, Aead } from '../src/identifiers';
import type { PreSharedKey } from '../src/interfaces/preSharedKey';
import { CipherSuite } from '../src/cipherSuite';

import {
  hexStringToBytes,
  bytesToCryptoKeyPair,
  kemToKeyGenAlgorithm,
} from './utils';

interface TestVectorEncryption {
  aad: string;
  ct: string;
  nonce: string;
  pt: string;
}

interface TestVectorExport {
  exporter_context: string;
  L: number;
  exported_value: string;
}

export interface TestVector {
  mode: number;
  kem_id: Kem;
  kdf_id: Kdf;
  aead_id: Aead;
  psk_id?: string;
  psk?: string;
  info: string;
  ikmR: string;
  ikmE: string;
  skRm: string;
  skSm?: string;
  skEm: string;
  pkRm: string;
  pkSm?: string;
  pkEm: string;
  enc: string;
  shared_secret: string;
  key_schedule_context: string;
  secret: string;
  key: string;
  base_nonce: string;
  exporter_secret: string;
  encryptions: Array<TestVectorEncryption>;
  exports: Array<TestVectorExport>;
}

export async function testConformance(v: TestVector) {

  // console.log(v.mode, "/", v.kem_id, "/", v.kdf_id, "/", v.aead_id);

  const info = hexStringToBytes(v.info);
  // const ikmE = hexStringToBytes(v.ikmE);
  const pkEm = hexStringToBytes(v.pkEm);
  const skEm = hexStringToBytes(v.skEm);
  let psk: PreSharedKey | undefined = undefined;
  if (v.psk !== undefined && v.psk_id !== undefined) {
    psk = { id: new ArrayBuffer(0), key: new ArrayBuffer(0) };
    psk.key = hexStringToBytes(v.psk);
    psk.id = hexStringToBytes(v.psk_id);
  }
  // const ikmR = hexStringToBytes(v.ikmR);
  const pkRm = hexStringToBytes(v.pkRm);
  const skRm = hexStringToBytes(v.skRm);
  let skp: CryptoKeyPair | undefined = undefined;
  let pks: CryptoKey | undefined = undefined;
  if (v.skSm !== undefined && v.pkSm !== undefined) {
    const skSm = hexStringToBytes(v.skSm);
    const pkSm = hexStringToBytes(v.pkSm);
    skp = await bytesToCryptoKeyPair(skSm, pkSm, kemToKeyGenAlgorithm(v.kem_id));
    pks = skp.publicKey;
  }
  const enc = hexStringToBytes(v.enc);

  const rkp = await bytesToCryptoKeyPair(skRm, pkRm, kemToKeyGenAlgorithm(v.kem_id));
  const ekp = await bytesToCryptoKeyPair(skEm, pkEm, kemToKeyGenAlgorithm(v.kem_id));

  const suite = new CipherSuite({ kem: v.kem_id, kdf: v.kdf_id, aead: v.aead_id });

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
}
