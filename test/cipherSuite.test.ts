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

  // RFC9180 A.1.
  describe('constructor with DhkemX25519HkdfSha256/HkdfSha256/Aes128Gcm', () => {
    it('should have ciphersuites', () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      // assert
      expect(suite.kem).toEqual(Kem.DhkemX25519HkdfSha256);
      expect(suite.kem).toEqual(0x0020);
      expect(suite.kdf).toEqual(Kdf.HkdfSha256);
      expect(suite.kdf).toEqual(0x0001);
      expect(suite.aead).toEqual(Aead.Aes128Gcm);
      expect(suite.aead).toEqual(0x0001);
    });
  });

  // RFC9180 A.2.
  describe('constructor with DhkemX25519HkdfSha256/HkdfSha256/ChaCha20Poly1305', () => {
    it('should have ciphersuites', () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Chacha20Poly1305,
      });

      // assert
      expect(suite.kem).toEqual(Kem.DhkemX25519HkdfSha256);
      expect(suite.kem).toEqual(0x0020);
      expect(suite.kdf).toEqual(Kdf.HkdfSha256);
      expect(suite.kdf).toEqual(0x0001);
      expect(suite.aead).toEqual(Aead.Chacha20Poly1305);
      expect(suite.aead).toEqual(0x0003);
    });
  });

  // RFC9180 A.3.
  describe('constructor with DhkemP256HkdfSha256/HkdfSha256/Aes128Gcm', () => {
    it('should have ciphersuites', () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      // assert
      expect(suite.kem).toEqual(Kem.DhkemP256HkdfSha256);
      expect(suite.kem).toEqual(0x0010);
      expect(suite.kdf).toEqual(Kdf.HkdfSha256);
      expect(suite.kdf).toEqual(0x0001);
      expect(suite.aead).toEqual(Aead.Aes128Gcm);
      expect(suite.aead).toEqual(0x0001);
    });
  });

  // RFC9180 A.4.
  describe('constructor with DhkemP256HkdfSha256/HkdfSha512/Aes128Gcm', () => {
    it('should have ciphersuites', () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes128Gcm,
      });

      // assert
      expect(suite.kem).toEqual(Kem.DhkemP256HkdfSha256);
      expect(suite.kem).toEqual(0x0010);
      expect(suite.kdf).toEqual(Kdf.HkdfSha512);
      expect(suite.kdf).toEqual(0x0003);
      expect(suite.aead).toEqual(Aead.Aes128Gcm);
      expect(suite.aead).toEqual(0x0001);
    });
  });

  // RFC9180 A.5.
  describe('constructor with DhkemP256HkdfSha256/HkdfSha256/ChaCha20Poly1305', () => {
    it('should have ciphersuites', () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Chacha20Poly1305,
      });

      // assert
      expect(suite.kem).toEqual(Kem.DhkemP256HkdfSha256);
      expect(suite.kem).toEqual(0x0010);
      expect(suite.kdf).toEqual(Kdf.HkdfSha256);
      expect(suite.kdf).toEqual(0x0001);
      expect(suite.aead).toEqual(Aead.Chacha20Poly1305);
      expect(suite.aead).toEqual(0x0003);
    });
  });

  // RFC9180 A.6.
  describe('constructor with DhkemP521HkdfSha512/HkdfSha512/Aes256Gcm', () => {
    it('should have ciphersuites', () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP521HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes256Gcm,
      });

      // assert
      expect(suite.kem).toEqual(Kem.DhkemP521HkdfSha512);
      expect(suite.kem).toEqual(0x0012);
      expect(suite.kdf).toEqual(Kdf.HkdfSha512);
      expect(suite.kdf).toEqual(0x0003);
      expect(suite.aead).toEqual(Aead.Aes256Gcm);
      expect(suite.aead).toEqual(0x0002);
    });
  });

  // RFC9180 A.7.
  describe('constructor with DhkemP256HkdfSha256/HkdfSha256/ExportOnly', () => {
    it('should have ciphersuites', () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      // assert
      expect(suite.kem).toEqual(Kem.DhkemP256HkdfSha256);
      expect(suite.kem).toEqual(0x0010);
      expect(suite.kdf).toEqual(Kdf.HkdfSha256);
      expect(suite.kdf).toEqual(0x0001);
      expect(suite.aead).toEqual(Aead.ExportOnly);
      expect(suite.aead).toEqual(0xFFFF);
    });
  });

  describe('constructor with invalid KEM id', () => {
    it('should throw InvalidParamError', () => {
      expect(() => {
        new CipherSuite({ kem: -1, kdf: Kdf.HkdfSha256, aead: Aead.Aes128Gcm });
      }).toThrow(errors.InvalidParamError);
      expect(() => {
        new CipherSuite({ kem: -1, kdf: Kdf.HkdfSha256, aead: Aead.Aes128Gcm });
      }).toThrow('InvalidParamError: Invalid KEM id');
    });
  });

  describe('constructor with invalid KDF id', () => {
    it('should throw InvalidParamError', () => {
      expect(() => {
        new CipherSuite({ kem: Kem.DhkemP256HkdfSha256, kdf: -1, aead: Aead.Aes128Gcm });
      }).toThrow(errors.InvalidParamError);
      expect(() => {
        new CipherSuite({ kem: Kem.DhkemP256HkdfSha256, kdf: -1, aead: Aead.Aes128Gcm });
      }).toThrow('InvalidParamError: Invalid KDF id');
    });
  });

  describe('constructor with invalid AEAD id', () => {
    it('should throw InvalidParamError', () => {
      expect(() => {
        new CipherSuite({ kem: Kem.DhkemP256HkdfSha256, kdf: Kdf.HkdfSha256, aead: -1 });
      }).toThrow(errors.InvalidParamError);
      expect(() => {
        new CipherSuite({ kem: Kem.DhkemP256HkdfSha256, kdf: Kdf.HkdfSha256, aead: -1 });
      }).toThrow('InvalidParamError: Invalid AEAD id');
    });
  });

  describe('A README example of Base mode', () => {
    it('should work normally', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('my-secret-message');
      await expect(recipient.seal(pt)).rejects.toThrow(errors.SealError);
      await expect(sender.open(ct)).rejects.toThrow(errors.OpenError);
    });
  });

  describe('A README example of Base mode (Kem.DhkemP384HkdfSha384/Kdf.HkdfSha384)', () => {
    it('should work normally', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('my-secret-message');
    });
  });

  describe('A README example of Base mode (Kem.DhkemX25519HkdfSha256/Kdf.HkdfSha384)', () => {
    it('should work normally', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('my-secret-message');
    });
  });

  describe('A README example of Base mode (ExportOnly)', () => {
    it('should work normally', async () => {

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

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      const te = new TextEncoder();

      // export
      const pskS = sender.export(te.encode('jugemujugemu'), 32);
      const pskR = recipient.export(te.encode('jugemujugemu'), 32);
      expect(pskR).toEqual(pskS);

      // other functions are disabled.
      await expect(sender.seal(te.encode('my-secret-message'))).rejects.toThrow(errors.NotSupportedError);
      await expect(sender.open(te.encode('xxxxxxxxxxxxxxxxx'))).rejects.toThrow(errors.NotSupportedError);
      await expect(sender.setupBidirectional(te.encode('a'), te.encode('b'))).rejects.toThrow(errors.NotSupportedError);
    });
  });

  describe('A README example of PSK mode', () => {
    it('should work normally', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        psk: {
          id: new TextEncoder().encode('our-pre-shared-key-id'),
          key: new TextEncoder().encode('our-pre-shared-key'),
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        psk: {
          id: new TextEncoder().encode('our-pre-shared-key-id'),
          key: new TextEncoder().encode('our-pre-shared-key'),
        },
      });

      // encrypt
      const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('my-secret-message');
    });
  });

  describe('A README example of Auth mode', () => {
    it('should work normally', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
      });

      // encrypt
      const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('my-secret-message');
    });
  });

  describe('A README example of AuthPSK mode', () => {
    it('should work normally', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
        psk: {
          id: new TextEncoder().encode('our-pre-shared-key-id'),
          key: new TextEncoder().encode('our-pre-shared-key'),
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
        psk: {
          id: new TextEncoder().encode('our-pre-shared-key-id'),
          key: new TextEncoder().encode('our-pre-shared-key'),
        },
      });

      // encrypt
      const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('my-secret-message');
    });
  });

  describe('createRecipientContext with a private key as recipientKey', () => {
    it('should work normally', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('my-secret-message');
    });
  });

  describe('createSenderContext with a privatekey as senderKey', () => {
    it('should work normally', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp.privateKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
      });

      // encrypt
      const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('my-secret-message');
    });
  });

  describe('seal and open (single-shot apis)', () => {
    it('should work normally', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      // encrypt
      const { ct, enc } = await suite.seal(
        {
          recipientPublicKey: rkp.publicKey,
        },
        new TextEncoder().encode('my-secret-message'),
      );

      // decrypt
      const pt = await suite.open(
        {
          recipientKey: rkp,
          enc: enc,
        },
        ct,
      );

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('my-secret-message');
    });
  });

  describe('bidirectional seal and open', () => {
    it('should work normally', async () => {

      const te = new TextEncoder();

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });
      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // setup bidirectional encryption
      await sender.setupBidirectional(te.encode('seed-for-key'), te.encode('seed-for-nonce'));
      await recipient.setupBidirectional(te.encode('seed-for-key'), te.encode('seed-for-nonce'));

      // encrypt
      const ct = await sender.seal(te.encode('my-secret-message'));

      // decrypt
      const pt = await recipient.open(ct);

      // encrypt reversely
      const rct = await recipient.seal(te.encode('my-secret-message'));

      // decrypt reversely
      const rpt = await sender.open(rct);

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('my-secret-message');
      expect(new TextDecoder().decode(rpt)).toEqual('my-secret-message');
    });
  });

  describe('seal empty byte string', () => {
    it('should work normally', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(new TextEncoder().encode(''));

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      expect(new TextDecoder().decode(pt)).toEqual('');
    });
  });

  describe('deriveKeyPair with too long ikm', () => {
    it('should throw InvalidParamError', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      await expect(suite.deriveKeyPair(
        (new Uint8Array(129)).buffer,
      )).rejects.toThrow(errors.InvalidParamError);

      await expect(suite.deriveKeyPair(
        (new Uint8Array(129)).buffer,
      )).rejects.toThrow('Too long ikm');
    });
  });

  describe('createSenderContext with too long info', () => {
    it('should throw InvalidParamError', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await expect(suite.createSenderContext({
        info: (new Uint8Array(129)).buffer,
        recipientPublicKey: rkp.publicKey,
      })).rejects.toThrow(errors.InvalidParamError);

      await expect(suite.createSenderContext({
        info: (new Uint8Array(129)).buffer,
        recipientPublicKey: rkp.publicKey,
      })).rejects.toThrow('Too long info');
    });
  });

  describe('createSenderContext with too long psk.key', () => {
    it('should throw InvalidParamError', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await expect(suite.createSenderContext({
        psk: {
          key: (new Uint8Array(129)).buffer,
          id: new Uint8Array([1, 2, 3, 4]),
        },
        recipientPublicKey: rkp.publicKey,
      })).rejects.toThrow(errors.InvalidParamError);

      await expect(suite.createSenderContext({
        psk: {
          key: (new Uint8Array(129)).buffer,
          id: new Uint8Array([1, 2, 3, 4]),
        },
        recipientPublicKey: rkp.publicKey,
      })).rejects.toThrow('Too long psk.key');
    });
  });

  describe('createSenderContext with too long psk.id', () => {
    it('should throw InvalidParamError', async () => {

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await expect(suite.createSenderContext({
        psk: {
          key: new Uint8Array([1, 2, 3, 4]),
          id: (new Uint8Array(129)).buffer,
        },
        recipientPublicKey: rkp.publicKey,
      })).rejects.toThrow(errors.InvalidParamError);

      await expect(suite.createSenderContext({
        psk: {
          key: new Uint8Array([1, 2, 3, 4]),
          id: (new Uint8Array(129)).buffer,
        },
        recipientPublicKey: rkp.publicKey,
      })).rejects.toThrow('Too long psk.id');
    });
  });
});
