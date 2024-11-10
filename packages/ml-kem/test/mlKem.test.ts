// import { assertEquals, assertRejects } from "@std/assert";
import { assertEquals } from "@std/assert";
import { dirname, fromFileUrl, join } from "@std/path";
import { describe, it } from "@std/testing/bdd";

import { concat, hexToBytes, isDeno, loadCrypto } from "@hpke/common";
import {
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
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
        const kp = await recipient.deriveKeyPair(sk);
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
          ekm: msg[i],
        });
        const ssR = await recipient.decap({
          enc: res.enc,
          recipientKey: kp.privateKey,
        });
        assertEquals(res.enc, ct[i]);
        assertEquals(res.sharedSecret, ss[i]);
        assertEquals(ssR, ss[i]);
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
        const kp = await recipient.deriveKeyPair(sk);
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
          ekm: msg[i],
        });
        const ssR = await recipient.decap({
          enc: res.enc,
          recipientKey: kp.privateKey,
        });
        assertEquals(res.enc, ct[i]);
        assertEquals(res.sharedSecret, ss[i]);
        assertEquals(ssR, ss[i]);
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
        const kp = await recipient.deriveKeyPair(sk);
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
          ekm: msg[i],
        });
        const ssR = await recipient.decap({
          enc: res.enc,
          recipientKey: kp.privateKey,
        });
        assertEquals(res.enc, ct[i]);
        assertEquals(res.sharedSecret, ss[i]);
        assertEquals(ssR, ss[i]);
      }
    });
  });

  // describe("official test vectors", () => {
  //   it("should match the results", async () => {
  //     for (const v of TEST_VECTORS) {
  //       const seed = hexToBytes(v.seed);
  //       const sk = hexToBytes(v.sk);
  //       const pk = hexToBytes(v.pk);
  //       const eseed = hexToBytes(v.eseed);
  //       const ct = hexToBytes(v.ct);
  //       const ss = hexToBytes(v.ss);
  //       assertEquals(seed.length, 32);
  //       assertEquals(sk.length, 32);
  //       assertEquals(pk.length, 1216);
  //       assertEquals(eseed.length, 64);
  //       assertEquals(ct.length, 1120);
  //       assertEquals(ss.length, 32);

  //       const recipient = new MlKem768();
  //       const kp = await recipient.generateKeyPairDerand(seed);
  //       assertEquals(
  //         (await recipient.serializePublicKey(kp.publicKey)).byteLength,
  //         1216,
  //       );
  //       assertEquals(
  //         new Uint8Array(await recipient.serializePrivateKey(kp.privateKey)),
  //         sk,
  //       );
  //       assertEquals(
  //         new Uint8Array(await recipient.serializePublicKey(kp.publicKey)),
  //         pk,
  //       );
  //       const sender = new MlKem768();
  //       const res = await sender.encap({
  //         recipientPublicKey: kp.publicKey,
  //         ekm: eseed,
  //       });
  //       const ssR = await recipient.decap({
  //         enc: res.enc,
  //         recipientKey: kp.privateKey,
  //       });
  //       assertEquals(res.enc.byteLength, 1120);
  //       assertEquals(res.sharedSecret.byteLength, 32);
  //       assertEquals(res.enc, ct);
  //       assertEquals(res.sharedSecret, ssR);
  //       assertEquals(res.sharedSecret, ss);
  //       // assertEquals(ssR, ss);
  //     }
  //   });
  // });

  // describe("importKey", () => {
  //   it("with valid raw - as ArrayBuffer", async () => {
  //     const kem = new MlKem768();
  //     const pkR = await kem.importKey(
  //       "raw",
  //       hexToBytes(
  //         "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
  //       ).buffer,
  //       true,
  //     );
  //     const skR = await kem.importKey(
  //       "raw",
  //       hexToBytes(
  //         "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
  //       ).buffer,
  //       false,
  //     );
  //     const res = await kem.encap({ recipientPublicKey: pkR });
  //     const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
  //     assertEquals(res.sharedSecret, ssR);
  //   });

  //   it("with valid raw - as Uint8Array", async () => {
  //     const kem = new MlKem768();
  //     const pkR = await kem.importKey(
  //       "raw",
  //       hexToBytes(
  //         "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
  //       ),
  //       true,
  //     );
  //     const skR = await kem.importKey(
  //       "raw",
  //       hexToBytes(
  //         "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
  //       ),
  //       false,
  //     );
  //     const res = await kem.encap({ recipientPublicKey: pkR });
  //     const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
  //     assertEquals(res.sharedSecret, ssR);
  //   });

  //   it("with valid jwk", async () => {
  //     const kem = new MlKem768();

  //     const jwkPkR = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: [],
  //     };
  //     const pkR = await kem.importKey("jwk", jwkPkR, true);

  //     const jwkSkR = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["deriveBits"],
  //     };

  //     const skR = await kem.importKey("jwk", jwkSkR, false);
  //     const res = await kem.encap({ recipientPublicKey: pkR });
  //     const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
  //     assertEquals(res.sharedSecret, ssR);
  //   });

  //   it("with valid jwk - private key with pub", async () => {
  //     const kem = new MlKem768();

  //     const jwkPkR = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: [],
  //     };
  //     const pkR = await kem.importKey("jwk", jwkPkR, true);

  //     const jwkSkR = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["deriveBits"],
  //     };

  //     const skR = await kem.importKey("jwk", jwkSkR, false);
  //     const res = await kem.encap({ recipientPublicKey: pkR });
  //     const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
  //     assertEquals(res.sharedSecret, ssR);
  //   });

  //   it("with valid jwk - public key without key_ops", async () => {
  //     const kem = new MlKem768();

  //     const jwkPkR = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       // key_ops: [],
  //     };
  //     const pkR = await kem.importKey("jwk", jwkPkR, true);

  //     const jwkSkR = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["deriveBits"],
  //     };

  //     const skR = await kem.importKey("jwk", jwkSkR, false);
  //     const res = await kem.encap({ recipientPublicKey: pkR });
  //     const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
  //     assertEquals(res.sharedSecret, ssR);
  //   });

  //   it("with invalid raw - public key with valid jwk", async () => {
  //     const kem = new MlKem768();
  //     const jwkPkR = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: [],
  //     };
  //     await assertRejects(
  //       () =>
  //         kem.importKey(
  //           "raw",
  //           jwkPkR,
  //           true,
  //         ),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid raw - public key with invalid length of the key", async () => {
  //     const kem = new MlKem768();
  //     await assertRejects(
  //       () =>
  //         kem.importKey(
  //           "raw",
  //           hexToBytes(
  //             "236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
  //           ),
  //           true,
  //         ),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid raw - private key with invalid length of the key", async () => {
  //     const kem = new MlKem768();
  //     await assertRejects(
  //       () =>
  //         kem.importKey(
  //           "raw",
  //           hexToBytes(
  //             "9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
  //           ),
  //           false,
  //         ),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - public key with valid raw key", async () => {
  //     const kem = new MlKem768();
  //     await assertRejects(
  //       () =>
  //         kem.importKey(
  //           "jwk",
  //           hexToBytes(
  //             "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
  //           ),
  //           true,
  //         ),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - public key with invalid kty", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "OKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: [],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, false),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - public key without kty", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       // kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: [],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, false),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - public key with invalid alg", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wind",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: [],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, false),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - public key without alg", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       // alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: [],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, false),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - public key with invalid length of the key", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "NrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: [],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, false),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - public key with priv", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: [],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, false),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - public key without pub", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       x: "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: [],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, false),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - public key with invalid key_ops including deriveBits", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: ["deriveBits"],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, true),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - public key with invalid key_ops including encrypt", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       key_ops: ["encrypt"],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, true),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - private key with invalid kty", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "OKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["deriveBits"],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, true),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - private key without kty", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       // kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["deriveBits"],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, true),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - private key with invalid alg", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wind",
  //       priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["deriveBits"],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, true),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - private key without alg", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       // alg: "X-Wing",
  //       priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["deriveBits"],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, true),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - private key with invalid length of the key", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       priv: "wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["deriveBits"],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, false),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - private key without priv", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       pub:
  //         "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
  //       // priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["deriveBits"],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, true),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - private key with invalid key_ops", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["encrypt"],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, true),
  //       DeserializeError,
  //     );
  //   });

  //   it("with invalid jwk - private key with invalid key_ops including a valid value", async () => {
  //     const kem = new MlKem768();

  //     const jwk = {
  //       kty: "AKP",
  //       kid: "01",
  //       alg: "X-Wing",
  //       priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
  //       key_ops: ["deriveBits", "encrypt"],
  //     };
  //     // assert
  //     await assertRejects(
  //       () => kem.importKey("jwk", jwk, true),
  //       DeserializeError,
  //     );
  //   });
  // });
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
        new TextEncoder().encode("Hello world!"),
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
        new TextEncoder().encode("Hello world!"),
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
        new TextEncoder().encode("Hellow world!"),
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
        new TextEncoder().encode("Hello world!"),
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
        new TextEncoder().encode("Hello world!"),
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
        new TextEncoder().encode("Hellow world!"),
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
        new TextEncoder().encode("Hello world!"),
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
        new TextEncoder().encode("Hello world!"),
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
        new TextEncoder().encode("Hellow world!"),
      );
      const pt = await recipient.open(encrypted);
      assertEquals(new TextDecoder().decode(pt), "Hellow world!");
    });
  });
});
