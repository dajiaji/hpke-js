/**
 * Test vectors from draft-ietf-cose-hpke-24.
 *
 * Parameters (from the spec):
 *   Plaintext:  "hpke test payload"
 *   AAD:        "external-aad"
 *   Info:       "external-info"
 *   HPKE AAD:   "external-hpke-aad"
 *
 * "default" means the empty byte string; "external" means the value above.
 */

import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { isDeno } from "@hpke/common";

import type { CoseEncrypt0 } from "../src/encrypt0.ts";
import type { CoseEncrypt } from "../src/encrypt.ts";
import { ContentAlg } from "../src/alg.ts";
import { decode } from "../src/cbor/decoder.ts";
import type { CborValue } from "../src/cbor/types.ts";

import { createHpke0, createHpke0Ke } from "../src/hpke0.ts";
import { createHpke1, createHpke1Ke } from "../src/hpke1.ts";
import { createHpke2, createHpke2Ke } from "../src/hpke2.ts";
import { createHpke3, createHpke3Ke } from "../src/hpke3.ts";
import { createHpke4, createHpke4Ke } from "../src/hpke4.ts";
import { createHpke5, createHpke5Ke } from "../src/hpke5.ts";
import { createHpke6, createHpke6Ke } from "../src/hpke6.ts";
import { createHpke7, createHpke7Ke } from "../src/hpke7.ts";

// ── helpers ──────────────────────────────────────────────────────────

function hex(s: string): Uint8Array {
  const bytes = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2) {
    bytes[i / 2] = parseInt(s.substring(i, i + 2), 16);
  }
  return bytes;
}

const PLAINTEXT = new TextEncoder().encode("hpke test payload");
const EXT_AAD = new TextEncoder().encode("external-aad");
const EXT_INFO = new TextEncoder().encode("external-info");
const EXT_HPKE_AAD = new TextEncoder().encode("external-hpke-aad");
const EMPTY = new Uint8Array(0);

// PSK parameters from draft-ietf-cose-hpke-24
const PSK_KEY = hex(
  "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
);
const PSK_ID = hex("456e6e796e20447572696e206172616e204d6f726961");

// ── algorithm configuration ─────────────────────────────────────────

interface AlgConfig {
  createIe: () => CoseEncrypt0;
  createKe: (contentAlg: ContentAlg) => CoseEncrypt;
}

const ALGS: Record<string, AlgConfig> = {
  "HPKE-0": {
    createIe: createHpke0,
    createKe: createHpke0Ke,
  },
  "HPKE-1": {
    createIe: createHpke1,
    createKe: createHpke1Ke,
  },
  "HPKE-2": {
    createIe: createHpke2,
    createKe: createHpke2Ke,
  },
  "HPKE-3": {
    createIe: createHpke3,
    createKe: createHpke3Ke,
  },
  "HPKE-4": {
    createIe: createHpke4,
    createKe: createHpke4Ke,
  },
  "HPKE-5": {
    createIe: createHpke5,
    createKe: createHpke5Ke,
  },
  "HPKE-6": {
    createIe: createHpke6,
    createKe: createHpke6Ke,
  },
  "HPKE-7": {
    createIe: createHpke7,
    createKe: createHpke7Ke,
  },
};

// Algorithms skipped on Deno (P-521 not supported in Deno's WebCrypto)
const DENO_SKIP_ALGS = new Set(["HPKE-2"]);

// Content alg mapping for KE: which content alg is used for each HPKE-X-KE
const KE_CONTENT_ALG: Record<string, ContentAlg> = {
  "HPKE-0-KE": ContentAlg.A128GCM,
  "HPKE-1-KE": ContentAlg.A256GCM,
  "HPKE-2-KE": ContentAlg.A256GCM,
  "HPKE-3-KE": ContentAlg.A128GCM,
  "HPKE-4-KE": ContentAlg.CHACHA20POLY1305,
  "HPKE-5-KE": ContentAlg.A256GCM,
  "HPKE-6-KE": ContentAlg.A256GCM,
  "HPKE-7-KE": ContentAlg.A256GCM,
};

// ── COSE_Key → CryptoKey import ─────────────────────────────────────

async function importPrivateKey(
  keyHex: string,
  algName: string,
): Promise<CryptoKey> {
  const keyMap = decode(hex(keyHex)) as Map<CborValue, CborValue>;
  const dBytes = keyMap.get(-4) as Uint8Array;

  // Create a temporary instance to access the KEM for key import
  const config = ALGS[algName];
  const ie = config.createIe();
  return await ie.suite.kem.importKey(
    "raw",
    dBytes.buffer as ArrayBuffer,
    false,
  );
}

// ── Test vector parser ──────────────────────────────────────────────

interface TestVector {
  label: string;
  ciphertextHex: string;
}

interface TestSection {
  algName: string; // e.g. "HPKE-3-KE" or "HPKE-3"
  keyHex: string;
  vectors: TestVector[];
  isPsk: boolean;
}

function parseTestVectors(text: string): TestSection[] {
  const lines = text.split("\n");
  const sections: TestSection[] = [];
  let currentSection: TestSection | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Match COSE_Key line
    const keyMatch = line.match(
      /^(HPKE-\d(?:-KE)?)\s+COSE_Key:+\s*([0-9a-f]+)$/,
    );
    if (keyMatch) {
      currentSection = {
        algName: keyMatch[1],
        keyHex: keyMatch[2],
        vectors: [],
        isPsk: false,
      };
      sections.push(currentSection);
      continue;
    }

    // Match test vector label (non-PSK)
    const keMatch = line.match(
      /^(HPKE-\d-KE) with (default|external) aad, (default|external) info, (default|external) hpke aad$/,
    );
    if (keMatch && currentSection) {
      currentSection.vectors.push({
        label: line,
        ciphertextHex: "",
      });
      continue;
    }

    const e0Match = line.match(
      /^(HPKE-\d) Encrypt0 with (default|external) aad and (default|external) info$/,
    );
    if (e0Match && currentSection) {
      currentSection.vectors.push({
        label: line,
        ciphertextHex: "",
      });
      continue;
    }

    // Match PSK test vector labels
    const kePskMatch = line.match(
      /^(HPKE-\d-KE) KE\+PSK with (default|external) aad, (default|external) info, (default|external) hpke aad$/,
    );
    if (kePskMatch && currentSection) {
      currentSection.isPsk = true;
      currentSection.vectors.push({
        label: line,
        ciphertextHex: "",
      });
      continue;
    }

    const e0PskMatch = line.match(
      /^(HPKE-\d) Encrypt0\+PSK with (default|external) aad and (default|external) info$/,
    );
    if (e0PskMatch && currentSection) {
      currentSection.isPsk = true;
      currentSection.vectors.push({
        label: line,
        ciphertextHex: "",
      });
      continue;
    }

    // Match Ciphertext line
    const ctMatch = line.match(/^Ciphertext:\s*([0-9a-f]+)$/);
    if (ctMatch && currentSection && currentSection.vectors.length > 0) {
      currentSection.vectors[currentSection.vectors.length - 1].ciphertextHex =
        ctMatch[1];
    }
  }

  return sections;
}

function parseParams(
  label: string,
): { aad: Uint8Array; info: Uint8Array; hpkeAad: Uint8Array } {
  const aad = label.includes("external aad") ? EXT_AAD : EMPTY;

  let info: Uint8Array;
  if (label.includes("external info")) {
    info = EXT_INFO;
  } else {
    info = EMPTY;
  }

  let hpkeAad: Uint8Array;
  if (label.includes("external hpke aad")) {
    hpkeAad = EXT_HPKE_AAD;
  } else {
    hpkeAad = EMPTY;
  }

  return { aad, info, hpkeAad };
}

// ── Load test vectors ───────────────────────────────────────────────

const tvText = Deno.readTextFileSync(
  new URL("./testvectors.txt", import.meta.url),
);
const allSections = parseTestVectors(tvText);

// ── Tests ───────────────────────────────────────────────────────────

describe("Test vectors (non-PSK)", () => {
  // KE (Key Encryption) test vectors
  const keSections = allSections.filter(
    (s) => s.algName.endsWith("-KE") && !s.isPsk,
  );

  for (const section of keSections) {
    const baseAlgName = section.algName.replace("-KE", "");
    const config = ALGS[baseAlgName];
    if (!config) continue;
    if (isDeno() && DENO_SKIP_ALGS.has(baseAlgName)) continue;

    const contentAlg = KE_CONTENT_ALG[section.algName];
    if (contentAlg === undefined) continue;

    describe(`KE: ${section.algName}`, () => {
      for (const tv of section.vectors) {
        if (!tv.ciphertextHex) continue;

        it(tv.label, async () => {
          const privateKey = await importPrivateKey(
            section.keyHex,
            baseAlgName,
          );
          const { aad, info, hpkeAad } = parseParams(tv.label);

          const enc = config.createKe(contentAlg);
          const pt = await enc.open(
            privateKey,
            hex(tv.ciphertextHex),
            {
              externalAad: aad,
              extraInfo: info,
              aad: hpkeAad,
            },
          );

          assertEquals(pt, PLAINTEXT);
        });
      }
    });
  }

  // Encrypt0 (Integrated Encryption) test vectors
  const e0Sections = allSections.filter(
    (s) => !s.algName.endsWith("-KE") && !s.isPsk,
  );

  for (const section of e0Sections) {
    const config = ALGS[section.algName];
    if (!config) continue;
    if (isDeno() && DENO_SKIP_ALGS.has(section.algName)) continue;

    describe(`Encrypt0: ${section.algName}`, () => {
      for (const tv of section.vectors) {
        if (!tv.ciphertextHex) continue;

        it(tv.label, async () => {
          const privateKey = await importPrivateKey(
            section.keyHex,
            section.algName,
          );
          const { aad, info } = parseParams(tv.label);

          const enc0 = config.createIe();
          const pt = await enc0.open(privateKey, hex(tv.ciphertextHex), {
            externalAad: aad,
            info,
          });

          assertEquals(pt, PLAINTEXT);
        });
      }
    });
  }
});

describe("Test vectors (PSK)", () => {
  // KE+PSK test vectors
  const kePskSections = allSections.filter(
    (s) => s.algName.endsWith("-KE") && s.isPsk,
  );

  for (const section of kePskSections) {
    const baseAlgName = section.algName.replace("-KE", "");
    const config = ALGS[baseAlgName];
    if (!config) continue;
    if (isDeno() && DENO_SKIP_ALGS.has(baseAlgName)) continue;

    const contentAlg = KE_CONTENT_ALG[section.algName];
    if (contentAlg === undefined) continue;

    describe(`KE+PSK: ${section.algName}`, () => {
      for (const tv of section.vectors) {
        if (!tv.ciphertextHex) continue;

        it(tv.label, async () => {
          const privateKey = await importPrivateKey(
            section.keyHex,
            baseAlgName,
          );
          const { aad, info, hpkeAad } = parseParams(tv.label);

          const enc = config.createKe(contentAlg);
          const pt = await enc.open(
            privateKey,
            hex(tv.ciphertextHex),
            {
              externalAad: aad,
              extraInfo: info,
              aad: hpkeAad,
              psk: { id: PSK_ID, key: PSK_KEY },
            },
          );

          assertEquals(pt, PLAINTEXT);
        });
      }
    });
  }

  // Encrypt0+PSK test vectors
  const e0PskSections = allSections.filter(
    (s) => !s.algName.endsWith("-KE") && s.isPsk,
  );

  for (const section of e0PskSections) {
    const config = ALGS[section.algName];
    if (!config) continue;
    if (isDeno() && DENO_SKIP_ALGS.has(section.algName)) continue;

    describe(`Encrypt0+PSK: ${section.algName}`, () => {
      for (const tv of section.vectors) {
        if (!tv.ciphertextHex) continue;

        it(tv.label, async () => {
          const privateKey = await importPrivateKey(
            section.keyHex,
            section.algName,
          );
          const { aad, info } = parseParams(tv.label);

          const enc0 = config.createIe();
          const pt = await enc0.open(privateKey, hex(tv.ciphertextHex), {
            externalAad: aad,
            info,
            psk: { id: PSK_ID, key: PSK_KEY },
          });

          assertEquals(pt, PLAINTEXT);
        });
      }
    });
  }
});
