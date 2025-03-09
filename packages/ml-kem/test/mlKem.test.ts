import { assertEquals, assertRejects } from "@std/assert";
import { dirname, fromFileUrl, join } from "@std/path";
import { describe, it } from "@std/testing/bdd";

import { concat, hexToBytes, isDeno, loadCrypto } from "@hpke/common";
import {
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  DeserializeError,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
  KemId,
} from "@hpke/core";
import { MlKem1024, MlKem512, MlKem768 } from "../mod.ts";

function getPath(name: string): string {
  const currentPath = dirname(fromFileUrl(import.meta.url));
  if (isDeno()) {
    return join(currentPath, name);
  }
  return join(currentPath, "../../", name);
}

function parseKAT(data: string) {
  const textByLine = data.trim().split("\n");
  const parsed: { [label: string]: Uint8Array[] } = {};

  for (let i = 0; i < textByLine.length; i++) {
    const [label, hexValue] = textByLine[i].split(" = ");
    if (label === "count") continue;
    const value = hexToBytes(hexValue);
    if (parsed[label]) {
      parsed[label].push(value);
    } else {
      parsed[label] = [value];
    }
  }

  return parsed;
}

describe("MlKem", () => {
  describe("constructor - MlKem512", () => {
    it("should have a correct ciphersuite", () => {
      const kem = new MlKem512();
      assertEquals(kem.secretSize, 32);
      assertEquals(kem.encSize, 768);
      assertEquals(kem.publicKeySize, 800);
      assertEquals(kem.privateKeySize, 64);
      assertEquals(kem.id, KemId.MlKem512);
      assertEquals(kem.id, 0x0040);
    });
  });

  describe("constructor - MlKem768", () => {
    it("should have a correct ciphersuite", () => {
      const kem = new MlKem768();
      assertEquals(kem.secretSize, 32);
      assertEquals(kem.encSize, 1088);
      assertEquals(kem.publicKeySize, 1184);
      assertEquals(kem.privateKeySize, 64);
      assertEquals(kem.id, KemId.MlKem768);
      assertEquals(kem.id, 0x0041);
    });
  });

  describe("constructor - MlKem1024", () => {
    it("should have a correct ciphersuite", () => {
      const kem = new MlKem1024();
      assertEquals(kem.secretSize, 32);
      assertEquals(kem.encSize, 1568);
      assertEquals(kem.publicKeySize, 1568);
      assertEquals(kem.privateKeySize, 64);
      assertEquals(kem.id, KemId.MlKem1024);
      assertEquals(kem.id, 0x0042);
    });
  });

  describe("official test vectors", () => {
    it("kat_MLKEM_512.rsp", async () => {
      const katData = await Deno.readTextFile(
        getPath("../../../test/vectors/kat/kat_MLKEM_512.rsp"),
      );
      const { z, d, ct, ss, msg, pk } = parseKAT(katData);

      for (let i = 0; i < z.length; i++) {
        const recipient = new MlKem512();
        const sk = concat(d[i], z[i]);
        const kp = await recipient.deriveKeyPair(sk.buffer as ArrayBuffer);
        assertEquals(
          new Uint8Array(await recipient.serializePrivateKey(kp.privateKey)),
          sk,
        );
        assertEquals(
          new Uint8Array(await recipient.serializePublicKey(kp.publicKey)),
          pk[i],
        );
        const sender = new MlKem512();
        const res = await sender.encap({
          recipientPublicKey: kp.publicKey,
          ekm: msg[i].buffer as ArrayBuffer,
        });
        const ssR = await recipient.decap({
          enc: res.enc,
          recipientKey: kp.privateKey,
        });
        assertEquals(res.enc, ct[i].buffer as ArrayBuffer);
        assertEquals(res.sharedSecret, ss[i].buffer as ArrayBuffer);
        assertEquals(ssR, ss[i].buffer as ArrayBuffer);
      }
    });

    it("kat_MLKEM_768.rsp", async () => {
      const katData = await Deno.readTextFile(
        getPath("../../../test/vectors/kat/kat_MLKEM_768.rsp"),
      );
      const { z, d, ct, ss, msg, pk } = parseKAT(katData);

      for (let i = 0; i < z.length; i++) {
        const recipient = new MlKem768();
        const sk = concat(d[i], z[i]);
        const kp = await recipient.deriveKeyPair(sk.buffer as ArrayBuffer);
        assertEquals(
          new Uint8Array(await recipient.serializePrivateKey(kp.privateKey)),
          sk,
        );
        assertEquals(
          new Uint8Array(await recipient.serializePublicKey(kp.publicKey)),
          pk[i],
        );
        const sender = new MlKem768();
        const res = await sender.encap({
          recipientPublicKey: kp.publicKey,
          ekm: msg[i].buffer as ArrayBuffer,
        });
        const ssR = await recipient.decap({
          enc: res.enc,
          recipientKey: kp.privateKey,
        });
        assertEquals(res.enc, ct[i].buffer as ArrayBuffer);
        assertEquals(res.sharedSecret, ss[i].buffer as ArrayBuffer);
        assertEquals(ssR, ss[i].buffer as ArrayBuffer);
      }
    });

    it("kat_MLKEM_1024.rsp", async () => {
      const katData = await Deno.readTextFile(
        getPath("../../../test/vectors/kat/kat_MLKEM_1024.rsp"),
      );
      const { z, d, ct, ss, msg, pk } = parseKAT(katData);

      for (let i = 0; i < z.length; i++) {
        const recipient = new MlKem1024();
        const sk = concat(d[i], z[i]);
        const kp = await recipient.deriveKeyPair(sk.buffer as ArrayBuffer);
        assertEquals(
          new Uint8Array(await recipient.serializePrivateKey(kp.privateKey)),
          sk,
        );
        assertEquals(
          new Uint8Array(await recipient.serializePublicKey(kp.publicKey)),
          pk[i],
        );
        const sender = new MlKem1024();
        const res = await sender.encap({
          recipientPublicKey: kp.publicKey,
          ekm: msg[i].buffer as ArrayBuffer,
        });
        const ssR = await recipient.decap({
          enc: res.enc,
          recipientKey: kp.privateKey,
        });
        assertEquals(res.enc, ct[i].buffer as ArrayBuffer);
        assertEquals(res.sharedSecret, ss[i].buffer as ArrayBuffer);
        assertEquals(ssR, ss[i].buffer as ArrayBuffer);
      }
    });
  });

  describe("importKey", () => {
    it("with valid raw - as ArrayBuffer", async () => {
      const kem = new MlKem768();
      const pkR = await kem.importKey(
        "raw",
        hexToBytes(
          "3f1b8a5cf5aa0cb148cfac766a30a78209a3ce97cb427a9e813254e0b6a99ae25370b583c275357ce3b4d6c60aafda03e99734e0e98eba56aeef821e92b8c1db43942a7c37c9977d79946fe0474df27b9cf3b12ca94bb06401d09150530bf82adfc4623bd7af97425984b8c53f51969ebc02d9b41aace79536e3282af5adedb6363d4a7bdbb06a69e24c892888f6710055bb644db60ba3b884204c03b07c2a8aca0249ac29ead77d5c879a790a09b850a55ef614cc73cf7f727223ba0d6353295c008c986aa9200349a0ac500e347ee1795a1a8369ab6151c27b1341cace56852ee76c6d3ccb8331b23cde8b224af9b2dee402d9605bbfa8401976419c57ab1686bda096b28cb654cd4a5db7c32598e01491e21b8cd54497f60fe2bc31d783928e382bfbf3332b754cf969b12aa58f438b4a57064129d4456009a172a59ab3b77cc84c76944b99a53445a529ac0a62ad490174a47324a5d34b81a682a69c0a8dd75f0de93c20e430266c23b00c4869f53c6fd0854ed3caf4544952b05ed3b3b0d6ca34f0f297f2e9a7c1187804a37a121a6ad2ab50daf475aa3a25e6c9a0d6a29def62cbd298050f5b307c053a5c8838b4c3357f3376653c3366fa6fe1025d1960c75ba643265c157a84c914d559f540c67ec1587394af7bd17830d5089d505906fa9f766a9b93909f5b6627cc05a0b2192cbfc2271b0b22d77a07ce551edaa6522d402b00003723c115936c97f54c88aa513482a05554c628e69448eb6a0ef6f346341c802bdab9b03ba0af297d9e8b938b9cabefa46722421a338a872d9a88b88c9f0eec46932c367cc58b83573d26036aaf5276e515b0f23059b40c848f638ace3703ee6c27d966990c7702ed23a0cd9ba4cf6169a668a1f0bb586b076692e1c215754ff6784bd91a248cb90f008a3eca59852c057966933a1a86b6e05b2fad91b28bc61648b041a7ac046ab8112b6ac2cb900fb5c09821dc4b0716b509e122dc97c6ed7342f6f49fb65559729c384763ba2d2bb8cf56ae36f3b269970ac54841213b24b792c949f3c775e70ac8f7cc53763ff638adc5113ec60075c1a79276ca473c113832954abe207bebf0cd0426c0e29733947256c7756bf9b50d82191a07f0ba5d5a154b0866e293473b4076a1e995f9d086a472c118ac22c216a839920660a331eee198df5b1a1595239d5780cda75f73c6765a46ae4aa34001939dfad92f7e124a5f2c628b259de9560bbf470cc69cc652dc29b93ba86a4990dce0af1a4524c199a692670caf748d16612feed711f88a505d552a6440aa0422626f185f6921a82ef925086028ae8562fc7610e1b1649ef0094d96b505fbb7f112896efac0d192af45d903ac7992bbe9bf30e2577e24581cbc4f73b180d04a69f540b39e19a4ae36aec4f21ade774965391bcaebc0af869cb63631327b421bec6726651b8758bfee73c591212d4ff981f6684c58b359c2d07fa1e601d6c5cbfdc964b31909cca37fff96204fb5688d92ca5a85758cf160e9b06ed18320a4b1b0c8e8196ae76a6f621972d17a4d64a7df04c5a4c333c3bc1acaab37709149a3b8ca082a8fbca13268a1b022230e2d630272cb9ff2e6655af17327f3b9807095f582be18bd3f4e0bb723eced69b0585629986548d722b03b5bbd157ac99dee1c0a9aa1",
        ).buffer as ArrayBuffer,
        true,
      );
      const skR = await kem.importKey(
        "raw",
        hexToBytes(
          "d69cfc64f84d4f33e4c54e166b7ff9283a394986a539b23987a10f39d2d9689b6de62e3465a55c9c78a07d265be8540b3e58b0801a124d07ff12b438d5202ea0",
        ).buffer as ArrayBuffer,
        false,
      );
      const res = await kem.encap({ recipientPublicKey: pkR });
      const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
      assertEquals(res.sharedSecret, ssR);
    });

    it("with valid raw - as Uint8Array", async () => {
      const kem = new MlKem768();
      const pkR = await kem.importKey(
        "raw",
        hexToBytes(
          "3f1b8a5cf5aa0cb148cfac766a30a78209a3ce97cb427a9e813254e0b6a99ae25370b583c275357ce3b4d6c60aafda03e99734e0e98eba56aeef821e92b8c1db43942a7c37c9977d79946fe0474df27b9cf3b12ca94bb06401d09150530bf82adfc4623bd7af97425984b8c53f51969ebc02d9b41aace79536e3282af5adedb6363d4a7bdbb06a69e24c892888f6710055bb644db60ba3b884204c03b07c2a8aca0249ac29ead77d5c879a790a09b850a55ef614cc73cf7f727223ba0d6353295c008c986aa9200349a0ac500e347ee1795a1a8369ab6151c27b1341cace56852ee76c6d3ccb8331b23cde8b224af9b2dee402d9605bbfa8401976419c57ab1686bda096b28cb654cd4a5db7c32598e01491e21b8cd54497f60fe2bc31d783928e382bfbf3332b754cf969b12aa58f438b4a57064129d4456009a172a59ab3b77cc84c76944b99a53445a529ac0a62ad490174a47324a5d34b81a682a69c0a8dd75f0de93c20e430266c23b00c4869f53c6fd0854ed3caf4544952b05ed3b3b0d6ca34f0f297f2e9a7c1187804a37a121a6ad2ab50daf475aa3a25e6c9a0d6a29def62cbd298050f5b307c053a5c8838b4c3357f3376653c3366fa6fe1025d1960c75ba643265c157a84c914d559f540c67ec1587394af7bd17830d5089d505906fa9f766a9b93909f5b6627cc05a0b2192cbfc2271b0b22d77a07ce551edaa6522d402b00003723c115936c97f54c88aa513482a05554c628e69448eb6a0ef6f346341c802bdab9b03ba0af297d9e8b938b9cabefa46722421a338a872d9a88b88c9f0eec46932c367cc58b83573d26036aaf5276e515b0f23059b40c848f638ace3703ee6c27d966990c7702ed23a0cd9ba4cf6169a668a1f0bb586b076692e1c215754ff6784bd91a248cb90f008a3eca59852c057966933a1a86b6e05b2fad91b28bc61648b041a7ac046ab8112b6ac2cb900fb5c09821dc4b0716b509e122dc97c6ed7342f6f49fb65559729c384763ba2d2bb8cf56ae36f3b269970ac54841213b24b792c949f3c775e70ac8f7cc53763ff638adc5113ec60075c1a79276ca473c113832954abe207bebf0cd0426c0e29733947256c7756bf9b50d82191a07f0ba5d5a154b0866e293473b4076a1e995f9d086a472c118ac22c216a839920660a331eee198df5b1a1595239d5780cda75f73c6765a46ae4aa34001939dfad92f7e124a5f2c628b259de9560bbf470cc69cc652dc29b93ba86a4990dce0af1a4524c199a692670caf748d16612feed711f88a505d552a6440aa0422626f185f6921a82ef925086028ae8562fc7610e1b1649ef0094d96b505fbb7f112896efac0d192af45d903ac7992bbe9bf30e2577e24581cbc4f73b180d04a69f540b39e19a4ae36aec4f21ade774965391bcaebc0af869cb63631327b421bec6726651b8758bfee73c591212d4ff981f6684c58b359c2d07fa1e601d6c5cbfdc964b31909cca37fff96204fb5688d92ca5a85758cf160e9b06ed18320a4b1b0c8e8196ae76a6f621972d17a4d64a7df04c5a4c333c3bc1acaab37709149a3b8ca082a8fbca13268a1b022230e2d630272cb9ff2e6655af17327f3b9807095f582be18bd3f4e0bb723eced69b0585629986548d722b03b5bbd157ac99dee1c0a9aa1",
        ).buffer as ArrayBuffer,
        true,
      );
      const skR = await kem.importKey(
        "raw",
        hexToBytes(
          "d69cfc64f84d4f33e4c54e166b7ff9283a394986a539b23987a10f39d2d9689b6de62e3465a55c9c78a07d265be8540b3e58b0801a124d07ff12b438d5202ea0",
        ).buffer as ArrayBuffer,
        false,
      );
      const res = await kem.encap({ recipientPublicKey: pkR });
      const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
      assertEquals(res.sharedSecret, ssR);
    });

    it("with valid jwk", async () => {
      const kem = new MlKem768();

      const jwkPkR = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: [],
      };
      const pkR = await kem.importKey("jwk", jwkPkR, true);

      const jwkSkR = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits"],
      };

      const skR = await kem.importKey("jwk", jwkSkR, false);
      const res = await kem.encap({ recipientPublicKey: pkR });
      const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
      assertEquals(res.sharedSecret, ssR);
    });

    it("with valid jwk - private key with pub", async () => {
      const kem = new MlKem768();

      const jwkPkR = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: [],
      };
      const pkR = await kem.importKey("jwk", jwkPkR, true);

      const jwkSkR = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits"],
      };

      const skR = await kem.importKey("jwk", jwkSkR, false);
      const res = await kem.encap({ recipientPublicKey: pkR });
      const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
      assertEquals(res.sharedSecret, ssR);
    });

    it("with valid jwk - public key without key_ops", async () => {
      const kem = new MlKem768();

      const jwkPkR = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        // key_ops: [],
      };
      const pkR = await kem.importKey("jwk", jwkPkR, true);

      const jwkSkR = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits"],
      };

      const skR = await kem.importKey("jwk", jwkSkR, false);
      const res = await kem.encap({ recipientPublicKey: pkR });
      const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
      assertEquals(res.sharedSecret, ssR);
    });

    it("with invalid raw - public key with valid jwk", async () => {
      const kem = new MlKem768();
      const jwkPkR = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: [],
      };
      await assertRejects(
        () =>
          kem.importKey(
            "raw",
            jwkPkR,
            true,
          ),
        DeserializeError,
      );
    });

    it("with invalid raw - public key with invalid length of the key", async () => {
      const kem = new MlKem768();
      await assertRejects(
        () =>
          kem.importKey(
            "raw",
            hexToBytes(
              "1b8a5cf5aa0cb148cfac766a30a78209a3ce97cb427a9e813254e0b6a99ae25370b583c275357ce3b4d6c60aafda03e99734e0e98eba56aeef821e92b8c1db43942a7c37c9977d79946fe0474df27b9cf3b12ca94bb06401d09150530bf82adfc4623bd7af97425984b8c53f51969ebc02d9b41aace79536e3282af5adedb6363d4a7bdbb06a69e24c892888f6710055bb644db60ba3b884204c03b07c2a8aca0249ac29ead77d5c879a790a09b850a55ef614cc73cf7f727223ba0d6353295c008c986aa9200349a0ac500e347ee1795a1a8369ab6151c27b1341cace56852ee76c6d3ccb8331b23cde8b224af9b2dee402d9605bbfa8401976419c57ab1686bda096b28cb654cd4a5db7c32598e01491e21b8cd54497f60fe2bc31d783928e382bfbf3332b754cf969b12aa58f438b4a57064129d4456009a172a59ab3b77cc84c76944b99a53445a529ac0a62ad490174a47324a5d34b81a682a69c0a8dd75f0de93c20e430266c23b00c4869f53c6fd0854ed3caf4544952b05ed3b3b0d6ca34f0f297f2e9a7c1187804a37a121a6ad2ab50daf475aa3a25e6c9a0d6a29def62cbd298050f5b307c053a5c8838b4c3357f3376653c3366fa6fe1025d1960c75ba643265c157a84c914d559f540c67ec1587394af7bd17830d5089d505906fa9f766a9b93909f5b6627cc05a0b2192cbfc2271b0b22d77a07ce551edaa6522d402b00003723c115936c97f54c88aa513482a05554c628e69448eb6a0ef6f346341c802bdab9b03ba0af297d9e8b938b9cabefa46722421a338a872d9a88b88c9f0eec46932c367cc58b83573d26036aaf5276e515b0f23059b40c848f638ace3703ee6c27d966990c7702ed23a0cd9ba4cf6169a668a1f0bb586b076692e1c215754ff6784bd91a248cb90f008a3eca59852c057966933a1a86b6e05b2fad91b28bc61648b041a7ac046ab8112b6ac2cb900fb5c09821dc4b0716b509e122dc97c6ed7342f6f49fb65559729c384763ba2d2bb8cf56ae36f3b269970ac54841213b24b792c949f3c775e70ac8f7cc53763ff638adc5113ec60075c1a79276ca473c113832954abe207bebf0cd0426c0e29733947256c7756bf9b50d82191a07f0ba5d5a154b0866e293473b4076a1e995f9d086a472c118ac22c216a839920660a331eee198df5b1a1595239d5780cda75f73c6765a46ae4aa34001939dfad92f7e124a5f2c628b259de9560bbf470cc69cc652dc29b93ba86a4990dce0af1a4524c199a692670caf748d16612feed711f88a505d552a6440aa0422626f185f6921a82ef925086028ae8562fc7610e1b1649ef0094d96b505fbb7f112896efac0d192af45d903ac7992bbe9bf30e2577e24581cbc4f73b180d04a69f540b39e19a4ae36aec4f21ade774965391bcaebc0af869cb63631327b421bec6726651b8758bfee73c591212d4ff981f6684c58b359c2d07fa1e601d6c5cbfdc964b31909cca37fff96204fb5688d92ca5a85758cf160e9b06ed18320a4b1b0c8e8196ae76a6f621972d17a4d64a7df04c5a4c333c3bc1acaab37709149a3b8ca082a8fbca13268a1b022230e2d630272cb9ff2e6655af17327f3b9807095f582be18bd3f4e0bb723eced69b0585629986548d722b03b5bbd157ac99dee1c0a9aa1",
            ).buffer as ArrayBuffer,
            true,
          ),
        DeserializeError,
      );
    });

    it("with invalid raw - private key with invalid length of the key", async () => {
      const kem = new MlKem768();
      await assertRejects(
        () =>
          kem.importKey(
            "raw",
            hexToBytes(
              "9cfc64f84d4f33e4c54e166b7ff9283a394986a539b23987a10f39d2d9689b6de62e3465a55c9c78a07d265be8540b3e58b0801a124d07ff12b438d5202ea0",
            ).buffer as ArrayBuffer,
            false,
          ),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with valid raw key", async () => {
      const kem = new MlKem768();
      await assertRejects(
        () =>
          kem.importKey(
            "jwk",
            hexToBytes(
              "3f1b8a5cf5aa0cb148cfac766a30a78209a3ce97cb427a9e813254e0b6a99ae25370b583c275357ce3b4d6c60aafda03e99734e0e98eba56aeef821e92b8c1db43942a7c37c9977d79946fe0474df27b9cf3b12ca94bb06401d09150530bf82adfc4623bd7af97425984b8c53f51969ebc02d9b41aace79536e3282af5adedb6363d4a7bdbb06a69e24c892888f6710055bb644db60ba3b884204c03b07c2a8aca0249ac29ead77d5c879a790a09b850a55ef614cc73cf7f727223ba0d6353295c008c986aa9200349a0ac500e347ee1795a1a8369ab6151c27b1341cace56852ee76c6d3ccb8331b23cde8b224af9b2dee402d9605bbfa8401976419c57ab1686bda096b28cb654cd4a5db7c32598e01491e21b8cd54497f60fe2bc31d783928e382bfbf3332b754cf969b12aa58f438b4a57064129d4456009a172a59ab3b77cc84c76944b99a53445a529ac0a62ad490174a47324a5d34b81a682a69c0a8dd75f0de93c20e430266c23b00c4869f53c6fd0854ed3caf4544952b05ed3b3b0d6ca34f0f297f2e9a7c1187804a37a121a6ad2ab50daf475aa3a25e6c9a0d6a29def62cbd298050f5b307c053a5c8838b4c3357f3376653c3366fa6fe1025d1960c75ba643265c157a84c914d559f540c67ec1587394af7bd17830d5089d505906fa9f766a9b93909f5b6627cc05a0b2192cbfc2271b0b22d77a07ce551edaa6522d402b00003723c115936c97f54c88aa513482a05554c628e69448eb6a0ef6f346341c802bdab9b03ba0af297d9e8b938b9cabefa46722421a338a872d9a88b88c9f0eec46932c367cc58b83573d26036aaf5276e515b0f23059b40c848f638ace3703ee6c27d966990c7702ed23a0cd9ba4cf6169a668a1f0bb586b076692e1c215754ff6784bd91a248cb90f008a3eca59852c057966933a1a86b6e05b2fad91b28bc61648b041a7ac046ab8112b6ac2cb900fb5c09821dc4b0716b509e122dc97c6ed7342f6f49fb65559729c384763ba2d2bb8cf56ae36f3b269970ac54841213b24b792c949f3c775e70ac8f7cc53763ff638adc5113ec60075c1a79276ca473c113832954abe207bebf0cd0426c0e29733947256c7756bf9b50d82191a07f0ba5d5a154b0866e293473b4076a1e995f9d086a472c118ac22c216a839920660a331eee198df5b1a1595239d5780cda75f73c6765a46ae4aa34001939dfad92f7e124a5f2c628b259de9560bbf470cc69cc652dc29b93ba86a4990dce0af1a4524c199a692670caf748d16612feed711f88a505d552a6440aa0422626f185f6921a82ef925086028ae8562fc7610e1b1649ef0094d96b505fbb7f112896efac0d192af45d903ac7992bbe9bf30e2577e24581cbc4f73b180d04a69f540b39e19a4ae36aec4f21ade774965391bcaebc0af869cb63631327b421bec6726651b8758bfee73c591212d4ff981f6684c58b359c2d07fa1e601d6c5cbfdc964b31909cca37fff96204fb5688d92ca5a85758cf160e9b06ed18320a4b1b0c8e8196ae76a6f621972d17a4d64a7df04c5a4c333c3bc1acaab37709149a3b8ca082a8fbca13268a1b022230e2d630272cb9ff2e6655af17327f3b9807095f582be18bd3f4e0bb723eced69b0585629986548d722b03b5bbd157ac99dee1c0a9aa1",
            ).buffer as ArrayBuffer,
            true,
          ),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with invalid kty", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "OKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key without kty", async () => {
      const kem = new MlKem768();

      const jwk = {
        // kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with invalid alg", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wind",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key without alg", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        // alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with invalid length of the key", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "uKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with priv", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key without pub", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        x: "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with invalid key_ops including deriveBits", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with invalid key_ops including encrypt", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: ["encrypt"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key with invalid kty", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "OKP",
        kid: "01",
        alg: "ML-KEM-768",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key without kty", async () => {
      const kem = new MlKem768();

      const jwk = {
        // kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key with invalid alg", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key without alg", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        // alg: "ML-KEM-768",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key with invalid length of the key", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        priv:
          "z8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key without priv", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        // priv:
        //   "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key with invalid key_ops", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["encrypt"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key with invalid key_ops including a valid value", async () => {
      const kem = new MlKem768();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits", "encrypt"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });
  });
});

describe("README examples", () => {
  describe("MlKem512/HkdfShar256/Aes256Gcm", () => {
    it("should work normally with generateKeyPair", async () => {
      const suite = new CipherSuite({
        kem: new MlKem512(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });
      const rkp = await suite.kem.generateKeyPair();
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });
      assertEquals(sender.enc.byteLength, suite.kem.encSize);
      const ct = await sender.seal(
        new TextEncoder().encode("Hello world!").buffer as ArrayBuffer,
      );
      const pt = await recipient.open(ct);
      assertEquals(new TextDecoder().decode(pt), "Hello world!");
    });

    it("should work normally with deriveKeyPair", async () => {
      const suite = new CipherSuite({
        kem: new MlKem512(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });
      const cryptoApi = await loadCrypto();
      const ikm = new Uint8Array(64);
      cryptoApi.getRandomValues(ikm);
      const rkp = await suite.kem.deriveKeyPair(ikm.buffer);
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });
      assertEquals(sender.enc.byteLength, suite.kem.encSize);
      const ct = await sender.seal(
        new TextEncoder().encode("Hello world!").buffer as ArrayBuffer,
      );
      const pt = await recipient.open(ct);
      assertEquals(new TextDecoder().decode(pt), "Hello world!");
    });

    it("should work normally with JWK", async () => {
      const suite = new CipherSuite({
        kem: new MlKem512(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      // NOTE: The following support for JWKs with the AKP key type is experimental.
      // Please be aware that the specifications are subject to change without notice.
      const jwkPub = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-512",
        pub:
          "gLcBAIMdfuFo9HOSSDEZ-Thj7LC8YFMS01coh2sA9fV69Mhe2pcoHVdDkLxyVhk2aNyYYlNUq1K5vOeBxXccwmCZ9vusvuF4TRlIh3MfCXyH4ILL6sV9MLe5opOHLIQUZvIkTMZf9LplPWdR36IgUdVTNplCwxwp-RMHr1cyktaXqMMWEuB7UzXPCDKf0ka_KjIgCoywxLA7nQnFuhw5GVOekinGlpJDSCgvaWsVJeVgOAa022GLPchjDLKG5DEXIbxQMfJXqpJb-AlgRFqo2OaXiOmdqVwdEMw76FhSjbDP6gA8dGk3gKZaNuYoQ7O-FUBlQ9Itg1B8h7J4Z5LID6VihFSjEDlN2kwqtZSThQJX1tO8EHGG2QYnB_NU6BoaEPy3Y9MaTsQJqiQ-0uWbsYmFXrFlYma7N1AHheoIzYjCIqjFOod3yrQsnCOKANWTaUJQJumdKuYECvZwkCnKh4nIl7Mp-6dI1pyKcUjJWrsMcXh8WPEvIfIhPjiSQqp_vTIMEqxCxhFgbLjB0bRiWIahRaU1vWW9DZlrMwwWV9Yah-kEFwAyJXWYIKO77FBc2vERkyKarhc80SutIqejCnap-nY2w9WqSOF4QBKgEvFBaLeFPSoW-QygLMM7IAbAjybBX8opYSzHkuHPAuEyGnWoEIkZhmZ9QUivNuZeGlkliQKWF3NMMVwOObdRjIZgzcJl0MgT7yCgQzF_rluOQFRu7PcdbAVPpmtJQBMJvvMP1RpVGXVdqRBGibJvCDkVTIR77yNllDwCSUg6rZpzZ8mAo9HORtIAihUnXKO8pINOb5owNsDNgLoijTS5eAJE1cDL6QfG-0OCSpwHRkcWOcuGGIxgw7JTIVzJFpK80Uk9akRNU2RG4CloE4ABzCh-DlGPOqJdjDuVs8NcWfSBnUhJdgKa8FomPDUzayYfd7LNwpOJ8ITATLs3DEhWK1tQdxwPuBaQjhmN1tU_duSL8ELCsfgqOkC42vUfRtdvpLzJ08iU_4UMD6oy4KwzkBpMeROfXyBBfsGhkGBwRPGLuCTPNQx4qz3fPCyGylVD9xU",
        key_ops: [],
      };
      const pk = await suite.kem.importKey("jwk", jwkPub, true);
      const sender = await suite.createSenderContext({
        recipientPublicKey: pk,
      });

      const jwkPriv = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-512",
        priv:
          "bbvEN1E23zsH98cOY54iPhd-f9U7Fhs_TVd5F5TxJiT2lkhASOwh-Wz1ClbQdZxEjzd5dS8Dg9N0SWkGlM96aA",
        key_ops: ["deriveBits"],
      };
      const sk = await suite.kem.importKey("jwk", jwkPriv, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: sk,
        enc: sender.enc,
      });
      const encrypted = await sender.seal(
        new TextEncoder().encode("Hellow world!").buffer as ArrayBuffer,
      );
      const pt = await recipient.open(encrypted);
      assertEquals(new TextDecoder().decode(pt), "Hellow world!");
    });
  });

  describe("MlKem768/HkdfShar256/Aes256Gcm", () => {
    it("should work normally with generateKeyPair", async () => {
      const suite = new CipherSuite({
        kem: new MlKem768(),
        kdf: new HkdfSha384(),
        aead: new Aes256Gcm(),
      });
      const rkp = await suite.kem.generateKeyPair();
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });
      assertEquals(sender.enc.byteLength, suite.kem.encSize);
      const ct = await sender.seal(
        new TextEncoder().encode("Hello world!").buffer as ArrayBuffer,
      );
      const pt = await recipient.open(ct);
      assertEquals(new TextDecoder().decode(pt), "Hello world!");
    });

    it("should work normally with deriveKeyPair", async () => {
      const suite = new CipherSuite({
        kem: new MlKem768(),
        kdf: new HkdfSha384(),
        aead: new Aes256Gcm(),
      });
      const cryptoApi = await loadCrypto();
      const ikm = new Uint8Array(64);
      cryptoApi.getRandomValues(ikm);
      const rkp = await suite.kem.deriveKeyPair(ikm.buffer);
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });
      assertEquals(sender.enc.byteLength, suite.kem.encSize);
      const ct = await sender.seal(
        new TextEncoder().encode("Hello world!").buffer as ArrayBuffer,
      );
      const pt = await recipient.open(ct);
      assertEquals(new TextDecoder().decode(pt), "Hello world!");
    });

    it("should work normally with JWK", async () => {
      const suite = new CipherSuite({
        kem: new MlKem768(),
        kdf: new HkdfSha384(),
        aead: new Aes256Gcm(),
      });

      // NOTE: The following support for JWKs with the AKP key type is experimental.
      // Please be aware that the specifications are subject to change without notice.
      const jwkPub = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        pub:
          "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
        key_ops: [],
      };
      const pk = await suite.kem.importKey("jwk", jwkPub, true);
      const sender = await suite.createSenderContext({
        recipientPublicKey: pk,
      });

      const jwkPriv = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-768",
        priv:
          "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
        key_ops: ["deriveBits"],
      };
      const sk = await suite.kem.importKey("jwk", jwkPriv, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: sk,
        enc: sender.enc,
      });
      const encrypted = await sender.seal(
        new TextEncoder().encode("Hellow world!").buffer as ArrayBuffer,
      );
      const pt = await recipient.open(encrypted);
      assertEquals(new TextDecoder().decode(pt), "Hellow world!");
    });
  });

  describe("MlKem1024/HkdfShar512/Aes256Gcm", () => {
    it("should work normally with generateKeyPair", async () => {
      const suite = new CipherSuite({
        kem: new MlKem1024(),
        kdf: new HkdfSha512(),
        aead: new Aes256Gcm(),
      });
      const rkp = await suite.kem.generateKeyPair();
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });
      assertEquals(sender.enc.byteLength, suite.kem.encSize);
      const ct = await sender.seal(
        new TextEncoder().encode("Hello world!").buffer as ArrayBuffer,
      );
      const pt = await recipient.open(ct);
      assertEquals(new TextDecoder().decode(pt), "Hello world!");
    });

    it("should work normally with deriveKeyPair", async () => {
      const suite = new CipherSuite({
        kem: new MlKem1024(),
        kdf: new HkdfSha512(),
        aead: new Aes256Gcm(),
      });
      const cryptoApi = await loadCrypto();
      const ikm = new Uint8Array(64);
      cryptoApi.getRandomValues(ikm);
      const rkp = await suite.kem.deriveKeyPair(ikm.buffer);
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });
      assertEquals(sender.enc.byteLength, suite.kem.encSize);
      const ct = await sender.seal(
        new TextEncoder().encode("Hello world!").buffer as ArrayBuffer,
      );
      const pt = await recipient.open(ct);
      assertEquals(new TextDecoder().decode(pt), "Hello world!");
    });

    it("should work normally with JWK", async () => {
      const suite = new CipherSuite({
        kem: new MlKem1024(),
        kdf: new HkdfSha512(),
        aead: new Aes256Gcm(),
      });

      // NOTE: The following support for JWKs with the AKP key type is experimental.
      // Please be aware that the specifications are subject to change without notice.
      const jwkPub = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-1024",
        pub:
          "_-qbP8sQI-m4OLtIUDODHFVkKGyQz9gL2OiV9hB45akvc_SCkTfFBUjJvBsJ8vxHanB0TeI1RdtC7sGqJjhD4ABZB8Gh_lq59oqr0Hs8CugzoQWHHVSdizRktTxm5dFl_HXJuGZEVSbC-BQTzvwmKjZdL1u-5bl7IYdsA0UWv-xooyV7mnKUaOWbPovLOWU4SFgrCEGRg6s5hcqXqphn7ooSGUcv0kM_JleI7hSrX2mSaQNihNhxcbwszXS9mnl2jRRZOVEWxyzDh5yU8WYFGTyWOsPBzoRf_uCTLOh7__FKf7CBnTEiAkLIV9A13_AAPOdIt4iuNAw4PvNr9Tp73YoDgfKEZDAXfYcEJ4hA-Xan3slvF1m0CjEobkhzC5m94II-CSldRDfF2nhzAyBfbhYXUqFTEwDQ5CiXilrKIHk77DC1d2w6YVm6kFsfyYnP6osioZnCgBUOn-TMAfw_R-iJZ9FpzEEmCZw6_2MxZlM4BKJX6MeYhqEaCTUGLts8pUyYX9IgdoNooErAk2qxXZR-ECQt75taKKZzGIGnLfsHlzieqIW2VdacJJs_xWMCo9gHf3kHY0U7xXUvk6i9tSoiaLMhvIYkNkkLXwimfaYpm_IAQkFuRjgx3elW7NJkNDFq1bcTDnGIJ5eyJpOxn4onsuhXJfiVCLoCJVx6rDwbOVlO5sokqzJ3RyVo_JElwkolGpqylHxOBIpcJUau8keZsmXEpnaVwoJiHIsewKtb3jo-UZU2nVVVCeY4ZBISzOCSngsOtkKLPTNNeMV3XeYk0hCvbZYdLPGHsxijBQx7CwJinjMf2RYXFwxSNWatjEQzSaPPO8iqpxN8wTcFNTxp5qZbpqB-z0GvTiyTRsAV-vUUkdUe08NpLScCcWW2-wGdicYJnLSPQ6pQUmEPcawgwmGAeXzB09pSEqu2srMMX_U0M4hIJiadb8trn8vKSJcfGgrQGvx2ayQFqSOdIEYrQdQAFaS6gRQUnjNjFBSQQCLJ_rkHv8aX5Wg_F5NXiMO7oNdit3mJGFt1hwmSDFOeTuxY7fsZiLGdwvjJW7mtQER5-ccj8Ge1iAYMVXh3H2cTukfAlfBexZIl_MI-CaVkU_yZuoQN2BxhnzxvQoMSzKq-16J8m7wkLtesFOIN5xqF-TmACVVRm5stojYvOdYEbkhmpguAiooG-9vDNzROXctzi0wda8SvyRi9_ZwI50SJ-himfUJMYpl87SK4JdQSzfQRqHwDWhInY_u-zLR_woRWnypZwFRtsdy1TKw0l4VJKtcH1CYq0jt114kKisARlwN5vWmQpmxx8wBgeDdNkFRtSNAItJLPakxiK8U5R8hparcKBCIJxyk0M-SISdpmn5MaWFcMo5EqEjMx6tNIYBVzVcpoKBqVbgCKX9hYm2EF0jdekWcXyRVhXOA3xcyTxmNDL1SCfPpg97c7JHSaUwoy14UxjBI_afYYA0WjDrV9LiKkquWUNDF31zZxMfIabHICf_F-UbJqXpSw0aQfo9JM7CCRAhh2y7NJPDtVkeaVNKcsl-YavYkEnHWJCua9nPe6c9A3iulEFMVFwvQgMNSwT7yWGMOIdSSp5jREqLmHKakjXAJbQ9rKVHW4hceU8xeU-9hT1RGeCsUC9vuRFiHHMGqYCWNx_vE0_JdzWsUeiLGke2JkESZjf-kcSwlMuTFSD2mCnYAM6PZIX0I8hbLL8FtAuGSkptG8I_GttmeQTxMTRryuzwgp6WdNrEKugaEfJvBCLGNehWsvBNpBrizOEVqj-fucJqMMfBAyteu1EyRu3OIFCPZ96zyhjslGooOVXFtyZcZ3eklr0ZNTIiYLMxF8FLeLx2cd29Ci-ZmF-_zC_5sW_5a-p0EloqCekxCxDKmegROt5NuEL6wRxnGYPtslVRUmxHiIK2SqWksIYZVeBqIs6vKFcLKyxnqMsdlaKqo-9LqBFZcnz1uhbaA6sXS0NfiTVSwa7dlRwqpGmmt9vUnE7LMjEPWRcSRomtzF4omBHyrOxOC7iSIuo-tBkIct5eEXJsQQuANWXdvcA_mCkgz-O7f1W5byWwqe0HHzsELQUZtBmoe-254",
        key_ops: [],
      };
      const pk = await suite.kem.importKey("jwk", jwkPub, true);
      const sender = await suite.createSenderContext({
        recipientPublicKey: pk,
      });

      const jwkPriv = {
        kty: "AKP",
        kid: "01",
        alg: "ML-KEM-1024",
        priv:
          "Y0cDVxEIKPJbI-3IDtKA7NOYqfUyUcMzJ1TeKvCxXpAequa7kbJ810jEAsQREUDVqULPPJX_eXf4jS71Fbsm0A",
        key_ops: ["deriveBits"],
      };
      const sk = await suite.kem.importKey("jwk", jwkPriv, false);
      const recipient = await suite.createRecipientContext({
        recipientKey: sk,
        enc: sender.enc,
      });
      const encrypted = await sender.seal(
        new TextEncoder().encode("Hellow world!").buffer as ArrayBuffer,
      );
      const pt = await recipient.open(encrypted);
      assertEquals(new TextDecoder().decode(pt), "Hellow world!");
    });
  });
});
