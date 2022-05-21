import { TextEncoder, TextDecoder } from 'util';

import { CipherSuite } from '../src/cipherSuite';
import { EncryptionContext } from '../src/encryptionContext';
import { Kem, Kdf, Aead } from '../src/identifiers';
import { KdfContext } from '../src/kdfContext';
import { isBrowser } from '../src/utils/misc';
import { loadSubtleCrypto } from '../src/webCrypto';

import * as errors from '../src/errors';

describe('CipherSuite', () => {

  // for jsdom setting.
  beforeAll(() => {
    if (isBrowser()) {
      Object.defineProperty(global.self, 'TextEncoder', TextEncoder);
      Object.defineProperty(global.self, 'TextDecoder', TextDecoder);
    }
  });

  describe('open by another recipient (AES-128-GCM)', () => {
    it('should throw OpenError', async () => {

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
      const ct2 = await recipient1.seal(new TextEncoder().encode('my-secret-message'));

      // assert
      await expect(recipient2.open(ct1)).rejects.toThrow(errors.OpenError);
      await expect(sender2.open(ct2)).rejects.toThrow(errors.OpenError);
    });
  });

  describe('open by another recipient (ChaCha20/Poly1305)', () => {
    it('should throw OpenError', async () => {

      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Chacha20Poly1305,
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
      const ct2 = await recipient1.seal(new TextEncoder().encode('my-secret-message'));

      // assert
      await expect(recipient2.open(ct1)).rejects.toThrow(errors.OpenError);
      await expect(sender2.open(ct2)).rejects.toThrow(errors.OpenError);
    });
  });

  describe('export with invalid argument', () => {
    it('should throw ExportError', async () => {

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

      // assert
      await expect(sender.export(te.encode('info'), -1)).rejects.toThrow(errors.ExportError);
    });
  });

  describe('export with invalid argument', () => {
    it('should throw ExportError', async () => {

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

      // assert
      await expect(sender.export(te.encode('info'), -1)).rejects.toThrow(errors.ExportError);
    });
  });

  describe('createSenderContext with invalid recipientPublicKey', () => {
    it('should throw ExportError', async () => {

      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkpX = await suiteX.generateKeyPair();

      // assert
      await expect(suite.createSenderContext({
        recipientPublicKey: rkpX.publicKey,
      })).rejects.toThrow(errors.EncapError);

      await expect(suite.createSenderContext({
        recipientPublicKey: rkpX.publicKey,
      })).rejects.toThrow('invalid public key for the ciphersuite');
    });
  });

  describe('createRecipientContext with invalid enc', () => {
    it('should throw DeserializeError', async () => {

      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const rkpX = await suiteX.generateKeyPair();

      const senderX = await suiteX.createSenderContext({
        recipientPublicKey: rkpX.publicKey,
      });

      // assert
      await expect(suite.createRecipientContext({
        recipientKey: rkp,
        enc: senderX.enc,
      })).rejects.toThrow(errors.DeserializeError);

      await expect(suite.createRecipientContext({
        recipientKey: rkp,
        enc: senderX.enc,
      })).rejects.toThrow('invalid public key for the ciphersuite');
    });
  });

  describe('createRecipientContext with invalid recipientKey', () => {
    it('should throw DecapError', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const rkpX = await suiteX.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      // assert
      await expect(suite.createRecipientContext({
        recipientKey: rkpX,
        enc: sender.enc,
      })).rejects.toThrow(errors.DecapError);

      await expect(suite.createRecipientContext({
        recipientKey: rkpX,
        enc: sender.enc,
      })).rejects.toThrow('invalid public key for the ciphersuite');
    });
  });

  describe('constructor without key info', () => {
    it('should throw Error', async () => {
      const api = await loadSubtleCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });
      const params = {
        aead: Aead.Aes128Gcm,
        nK: 16,
        nN: 12,
        nT: 16,
        exporterSecret: new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]),
      };

      // assert
      expect(() => {
        new EncryptionContext(api, kdf, params);
      }).toThrow('Required parameters are missing');
    });
  });

  describe('constructor with invalid aead id', () => {
    it('should throw Error', async () => {
      const api = await loadSubtleCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const key = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer;
      const baseNonce = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1]);
      const seq = 0;

      const params = {
        aead: Aead.ExportOnly, // invalid
        nK: 16,
        nN: 12,
        nT: 16,
        exporterSecret: new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer,
        key: key,
        baseNonce: baseNonce,
        seq: seq,
      };

      // assert
      expect(() => {
        new EncryptionContext(api, kdf, params);
      }).toThrow('Invalid or unsupported AEAD id');
    });
  });

  // describe('incrementSeq reaches upper limit', () => {
  //   it('should throw Error', async () => {
  //     const api = await loadSubtleCrypto();
  //     const kdf = new KdfContext(api, {
  //       kem: Kem.DhkemP256HkdfSha256,
  //       kdf: Kdf.HkdfSha256,
  //       aead: Aead.Aes128Gcm,
  //     });

  //     const key = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer;
  //     const baseNonce = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1]);
  //     const seq = Number.MAX_SAFE_INTEGER;

  //     const params = {
  //       aead: Aead.Aes128Gcm,
  //       nK: 16,
  //       nN: 12,
  //       nT: 16,
  //       exporterSecret: new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer,
  //       key: key,
  //       baseNonce: baseNonce,
  //       seq: seq,
  //     };
  //     const ec = new EncryptionContext(api, kdf, params);
  //     let ki = { key: createAeadKey(Aead.Aes128Gcm, key, api), baseNonce: baseNonce, seq: seq };
  //     ec.incrementSeq(ki);
  //     expect(() => { ec.incrementSeq(ki); }).toThrow(errors.MessageLimitReachedError);
  //     expect(() => { ec.incrementSeq(ki); }).toThrow('Message limit reached');
  //   });
  // });

  describe('setupBidirectional with invalid _nK', () => {
    it('should throw Error', async () => {
      const api = await loadSubtleCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const key = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer;
      const baseNonce = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1]);
      const seq = 0;

      const params = {
        aead: Aead.Aes128Gcm,
        nK: -1, // invalid
        nN: 12,
        nT: 16,
        exporterSecret: new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer,
        key: key,
        baseNonce: baseNonce,
        seq: seq,
      };

      const te = new TextEncoder();
      const ec = new EncryptionContext(api, kdf, params);

      // assert
      await expect(ec.setupBidirectional(te.encode('jyugemu'), te.encode('jyugemu'))).rejects.toThrow(errors.ExportError);
    });
  });

  describe('setupBidirectional with invalid _nN', () => {
    it('should throw Error', async () => {
      const api = await loadSubtleCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const key = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer;
      const baseNonce = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1]);
      const seq = 0;

      const params = {
        aead: Aead.Aes128Gcm,
        nK: 16,
        nN: -1, // invalid
        nT: 16,
        exporterSecret: new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer,
        key: key,
        baseNonce: baseNonce,
        seq: seq,
      };

      const te = new TextEncoder();
      const ec = new EncryptionContext(api, kdf, params);

      // assert
      await expect(ec.setupBidirectional(te.encode('jyugemu'), te.encode('jyugemu'))).rejects.toThrow(errors.ExportError);
    });
  });

});
