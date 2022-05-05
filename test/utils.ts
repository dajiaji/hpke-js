import { Kem } from '../src/identifiers';

export function hexStringToBytes(v: string): Uint8Array {
  const res = v.match(/[\da-f]{2}/gi);
  if (res == null) {
    throw new Error('Not hex string.');
  }
  return new Uint8Array(res.map(function (h) {
    return parseInt(h, 16);
  }));
}

export function bytesToBase64Url(v: Uint8Array): string {
  return btoa(String.fromCharCode(...v))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=*$/g, '');
}

export async function bytesToCryptoKeyPair(skm: Uint8Array, pkm: Uint8Array, alg: EcKeyGenParams): Promise<CryptoKeyPair> {
  const pk = await window.crypto.subtle.importKey('raw', pkm, alg, true, ['deriveKey', 'deriveBits']);
  const jwk = await window.crypto.subtle.exportKey('jwk', pk);
  jwk['d'] = bytesToBase64Url(skm);
  const sk = await window.crypto.subtle.importKey('jwk', jwk, alg, true, ['deriveKey', 'deriveBits']);
  return { privateKey: sk, publicKey: pk };
}

export function kemToKeyGenAlgorithm(kem: Kem): EcKeyGenParams {
  switch (kem) {
    case Kem.DhkemP256HkdfSha256:
      return {
        name: 'ECDH',
        namedCurve: 'P-256',
      };
    case Kem.DhkemP384HkdfSha384:
      return {
        name: 'ECDH',
        namedCurve: 'P-384',
      };
    default:
      // case Kem.DhkemP521HkdfSha512:
      return {
        name: 'ECDH',
        namedCurve: 'P-521',
      };
  }
}
