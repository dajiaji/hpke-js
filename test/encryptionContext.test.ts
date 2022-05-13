import { TextEncoder, TextDecoder } from 'util';

import { isBrowser } from '../src/utils/misc';
import { Kem, Kdf, Aead } from '../src/identifiers';
import { CipherSuite } from '../src/cipherSuite';

import * as errors from '../src/errors';

describe('CipherSuite', () => {

  // for jsdom setting.
  beforeAll(() => {
    if (isBrowser()) {
      Object.defineProperty(global.self, 'TextEncoder', TextEncoder);
      Object.defineProperty(global.self, 'TextDecoder', TextDecoder);
    }
  });

  describe('open by invalid recipient', () => {
    it('should throw OpenError', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp1 = await suite.generateKeyPair();
      const rkp2 = await suite.generateKeyPair();

      const sender1 = await suite.createSenderContext({
        recipientPublicKey: rkp1.publicKey,
      });

      const recipient1 = await suite.createRecipientContext({
        recipientKey: rkp1,
        enc: sender1.enc,
      });

      const te = new TextEncoder();

      await sender1.setupBidirectional(te.encode('seed-for-key'), te.encode('seed-for-nonce'));
      await recipient1.setupBidirectional(te.encode('seed-for-key'), te.encode('seed-for-nonce'));

      const sender2 = await suite.createSenderContext({
        recipientPublicKey: rkp2.publicKey,
      });

      const recipient2 = await suite.createRecipientContext({
        recipientKey: rkp2,
        enc: sender2.enc,
      });

      await sender2.setupBidirectional(te.encode('seed-for-key'), te.encode('seed-for-nonce'));
      await recipient2.setupBidirectional(te.encode('seed-for-key'), te.encode('seed-for-nonce'));

      const ct1 = await sender1.seal(new TextEncoder().encode('my-secret-message'));
      expect(async () => { await recipient2.open(ct1); }).rejects.toThrow(errors.OpenError);

      const ct2 = await recipient1.seal(new TextEncoder().encode('my-secret-message'));
      expect(async () => { await sender2.open(ct2); }).rejects.toThrow(errors.OpenError);
    });
  });

  describe('export with invalid argument', () => {
    it('should throw ExportError', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const te = new TextEncoder();
      expect(async () => { await sender.export(te.encode('info'), -1); }).rejects.toThrow(errors.ExportError);
    });
  });

});
