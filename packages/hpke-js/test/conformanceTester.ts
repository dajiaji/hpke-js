import { assertEquals, assertRejects } from "@std/assert";

import type { PreSharedKey, XCryptoKey } from "@hpke/common";
import {
  AeadId,
  DecapError,
  DeserializeError,
  hexToBytes,
  KdfId,
  KemId,
  kemToKeyGenAlgorithm,
  loadSubtleCrypto,
  NotSupportedError,
} from "@hpke/common";
import type { TestVector } from "./testVector.ts";

import { CipherSuite } from "../mod.ts";

export class ConformanceTester {
  protected _api: SubtleCrypto;
  private _count = 0;

  constructor(api: SubtleCrypto) {
    this._api = api;
  }

  public count(): number {
    return this._count;
  }

  public async test(v: TestVector) {
    const suite = new CipherSuite({
      kem: v.kem_id,
      kdf: v.kdf_id,
      aead: v.aead_id,
    });

    // importKey
    const pkEm = hexToBytes(v.pkEm).buffer as ArrayBuffer;
    const skEm = hexToBytes(v.skEm).buffer as ArrayBuffer;
    const pkRm = hexToBytes(v.pkRm).buffer as ArrayBuffer;
    const skRm = hexToBytes(v.skRm).buffer as ArrayBuffer;
    let skp: CryptoKeyPair | undefined = undefined;
    let pks: CryptoKey | undefined = undefined;
    if (v.skSm !== undefined && v.pkSm !== undefined) {
      const skSm = hexToBytes(v.skSm).buffer as ArrayBuffer;
      const pkSm = hexToBytes(v.pkSm).buffer as ArrayBuffer;
      skp = {
        privateKey: await suite.kem.importKey("raw", skSm, false),
        publicKey: await suite.kem.importKey("raw", pkSm, true),
      };
      pks = skp.publicKey;
    }
    const rkp = {
      privateKey: await suite.kem.importKey("raw", skRm, false),
      publicKey: await suite.kem.importKey("raw", pkRm, true),
    };

    const dSkR = await suite.kem.deserializePrivateKey(skRm);
    const dPkR = await suite.kem.deserializePublicKey(pkRm);
    const skRm2 = await suite.kem.serializePrivateKey(dSkR);
    const pkRm2 = await suite.kem.serializePublicKey(dPkR);
    assertEquals(skRm, skRm2);
    assertEquals(pkRm, pkRm2);

    const ekp = {
      privateKey: await suite.kem.importKey("raw", skEm, false),
      publicKey: await suite.kem.importKey("raw", pkEm), // true can be omitted
    };

    // deriveKeyPair
    const ikmE = hexToBytes(v.ikmE);
    const ikmR = hexToBytes(v.ikmR);
    const derivedR = await suite.kem.deriveKeyPair(ikmR.buffer as ArrayBuffer);
    const derivedPkRm = (await this.cryptoKeyToBytes(
      derivedR.publicKey,
      kemToKeyGenAlgorithm(v.kem_id),
    )).buffer as ArrayBuffer;
    assertEquals(derivedPkRm, pkRm);
    const derivedE = await suite.kem.deriveKeyPair(ikmE.buffer as ArrayBuffer);
    const derivedPkEm = (await this.cryptoKeyToBytes(
      derivedE.publicKey,
      kemToKeyGenAlgorithm(v.kem_id),
    )).buffer as ArrayBuffer;
    assertEquals(derivedPkEm, pkEm);

    // create EncryptionContext
    const info = hexToBytes(v.info).buffer as ArrayBuffer;
    let psk: PreSharedKey | undefined = undefined;
    if (v.psk !== undefined && v.psk_id !== undefined) {
      psk = { id: new ArrayBuffer(0), key: new ArrayBuffer(0) };
      psk.key = hexToBytes(v.psk).buffer as ArrayBuffer;
      psk.id = hexToBytes(v.psk_id).buffer as ArrayBuffer;
    }
    const enc = hexToBytes(v.enc);

    const sender = await suite.createSenderContext({
      info: info,
      psk: psk,
      recipientPublicKey: rkp.publicKey,
      senderKey: skp,
      ekm: ekp, // FOR DEBUGGING/TESTING PURPOSES ONLY.
    });
    assertEquals(new Uint8Array(sender.enc), enc);

    const recipient = await suite.createRecipientContext({
      info: info,
      psk: psk,
      recipientKey: rkp,
      enc: sender.enc,
      senderPublicKey: pks,
    });

    // seal and open
    if (v.aead_id !== 0xFFFF) {
      for (const ve of v.encryptions) {
        const pt = hexToBytes(ve.pt).buffer as ArrayBuffer;
        const aad = hexToBytes(ve.aad).buffer as ArrayBuffer;
        const ct = hexToBytes(ve.ct).buffer as ArrayBuffer;

        const sealed = await sender.seal(pt, aad);
        const opened = await recipient.open(sealed, aad);
        assertEquals(sealed, ct);
        assertEquals(opened, pt);
      }
    }

    // export
    for (const ve of v.exports) {
      const ec = ve.exporter_context.length === 0
        ? new ArrayBuffer(0)
        : hexToBytes(ve.exporter_context).buffer as ArrayBuffer;
      const ev = hexToBytes(ve.exported_value);

      let exported = await sender.export(ec, ve.L);
      assertEquals(new Uint8Array(exported), ev);
      exported = await recipient.export(ec, ve.L);
      assertEquals(new Uint8Array(exported), ev);
    }
    this._count++;
  }

  public async testValidEcPublicKey(crv: string, pk: string) {
    let kemId: KemId;
    let nPk: number;
    switch (crv) {
      case "P-256":
        kemId = KemId.DhkemP256HkdfSha256;
        nPk = 65;
        break;
      case "P-384":
        kemId = KemId.DhkemP384HkdfSha384;
        nPk = 97;
        break;
      case "P-521":
        kemId = KemId.DhkemP521HkdfSha512;
        nPk = 133;
        break;
      default:
        throw new Error("Invalid crv");
    }

    const suite = new CipherSuite({
      kem: kemId,
      kdf: KdfId.HkdfSha256,
      aead: AeadId.Aes128Gcm,
    });
    const rkp = await suite.kem.generateKeyPair();

    const pkb = hexToBytes(pk);
    const alg = kemToKeyGenAlgorithm(kemId);

    const cpk = await this._api.importKey("raw", pkb, alg, true, []);
    const sender = await suite.createSenderContext({
      recipientPublicKey: cpk,
    });
    await assertRejects(
      () => sender.open(new Uint8Array([1, 2, 3, 4]).buffer as ArrayBuffer),
      NotSupportedError,
    );

    if (pkb.length < nPk) {
      // Compressed public key not supported.
      return;
    }
    const recipient = await suite.createRecipientContext({
      recipientKey: rkp,
      enc: pkb.buffer as ArrayBuffer,
    });

    // assert
    await assertRejects(
      () => recipient.seal(new Uint8Array([1, 2, 3, 4]).buffer as ArrayBuffer),
      NotSupportedError,
    );
    this._count++;
  }

  public async testInvalidEcPublicKey(crv: string, pk: string) {
    let kemId: KemId;
    switch (crv) {
      case "P-256":
        kemId = KemId.DhkemP256HkdfSha256;
        break;
      case "P-384":
        kemId = KemId.DhkemP384HkdfSha384;
        break;
      case "P-521":
        kemId = KemId.DhkemP521HkdfSha512;
        break;
      default:
        throw new Error("Invalid crv");
    }

    const suite = new CipherSuite({
      kem: kemId,
      kdf: KdfId.HkdfSha256,
      aead: AeadId.Aes128Gcm,
    });
    const rkp = await suite.kem.generateKeyPair();

    const pkb = hexToBytes(pk).buffer as ArrayBuffer;

    // assert
    await assertRejects(
      () => suite.kem.importKey("raw", pkb),
      DeserializeError,
    );
    await assertRejects(
      () => suite.kem.importKey("raw", pkb),
      "Invalid key for the ciphersuite",
    );
    await assertRejects(() =>
      suite.createRecipientContext({
        recipientKey: rkp,
        enc: pkb,
      }), DeserializeError);
    await assertRejects(() =>
      suite.createRecipientContext({
        recipientKey: rkp,
        enc: pkb,
      }), "Invalid public key for the ciphersuite");
    this._count++;
  }

  public async testValidX25519PublicKey(pk: string) {
    const suite = new CipherSuite({
      kem: KemId.DhkemX25519HkdfSha256,
      kdf: KdfId.HkdfSha256,
      aead: AeadId.Aes128Gcm,
    });
    const rkp = await suite.kem.generateKeyPair();

    const pkb = hexToBytes(pk).buffer as ArrayBuffer;

    const recipient = await suite.createRecipientContext({
      recipientKey: rkp,
      enc: pkb,
    });

    // assert
    await assertRejects(
      () => recipient.seal(new Uint8Array([1, 2, 3, 4]).buffer as ArrayBuffer),
      NotSupportedError,
    );
    this._count++;
  }

  public async testInvalidX25519PublicKey(pk: string) {
    const suite = new CipherSuite({
      kem: KemId.DhkemX25519HkdfSha256,
      kdf: KdfId.HkdfSha256,
      aead: AeadId.Aes128Gcm,
    });
    const rkp = await suite.kem.generateKeyPair();

    const pkb = hexToBytes(pk).buffer as ArrayBuffer;

    // assert
    await assertRejects(() =>
      suite.createRecipientContext({
        recipientKey: rkp,
        enc: pkb,
      }), DecapError);
    this._count++;
  }

  public async testValidX448PublicKey(pk: string) {
    const suite = new CipherSuite({
      kem: KemId.DhkemX448HkdfSha512,
      kdf: KdfId.HkdfSha256,
      aead: AeadId.Aes128Gcm,
    });
    const rkp = await suite.kem.generateKeyPair();

    const pkb = hexToBytes(pk).buffer as ArrayBuffer;

    const recipient = await suite.createRecipientContext({
      recipientKey: rkp,
      enc: pkb,
    });

    // assert
    await assertRejects(
      () => recipient.seal(new Uint8Array([1, 2, 3, 4]).buffer as ArrayBuffer),
      NotSupportedError,
    );
    this._count++;
  }

  public async testInvalidX448PublicKey(pk: string) {
    const suite = new CipherSuite({
      kem: KemId.DhkemX448HkdfSha512,
      kdf: KdfId.HkdfSha256,
      aead: AeadId.Aes128Gcm,
    });
    const rkp = await suite.kem.generateKeyPair();

    const pkb = hexToBytes(pk).buffer as ArrayBuffer;

    // assert
    if (pkb.byteLength !== 56) {
      await assertRejects(() =>
        suite.createRecipientContext({
          recipientKey: rkp,
          enc: pkb,
        }), DeserializeError);
    } else {
      await assertRejects(() =>
        suite.createRecipientContext({
          recipientKey: rkp,
          enc: pkb,
        }), DecapError);
    }
    this._count++;
  }

  private async cryptoKeyToBytes(
    ck: CryptoKey,
    alg: KeyAlgorithm,
  ): Promise<Uint8Array> {
    if (alg.name === "ECDH") {
      return new Uint8Array(await this._api.exportKey("raw", ck));
    }
    // X25519
    return (ck as XCryptoKey).key;
  }
}

export async function createConformanceTester(): Promise<ConformanceTester> {
  const api = await loadSubtleCrypto();
  return new ConformanceTester(api);
}
