import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { DeserializeError, hexToBytes, loadCrypto } from "@hpke/common";
import { Aes256Gcm, CipherSuite, HkdfSha256, KemId } from "@hpke/core";
import { XWing } from "../mod.ts";
import { TEST_VECTORS } from "./testVectors.ts";

// function bytesToBase64Url(v: Uint8Array): string {
//   return btoa(String.fromCharCode(...v))
//     .replace(/\+/g, "-")
//     .replace(/\//g, "_")
//     .replace(/=*$/g, "");
// }

describe("XWing", () => {
  describe("constructor", () => {
    it("should have a correct ciphersuite", () => {
      const kem = new XWing();
      assertEquals(kem.secretSize, 32);
      assertEquals(kem.encSize, 1120);
      assertEquals(kem.publicKeySize, 1216);
      assertEquals(kem.privateKeySize, 32);
      assertEquals(kem.id, KemId.XWing);
      assertEquals(kem.id, 0x647a);
    });
  });

  describe("official test vectors", () => {
    it("should match the results", async () => {
      for (const v of TEST_VECTORS) {
        const seed = hexToBytes(v.seed);
        const sk = hexToBytes(v.sk);
        const pk = hexToBytes(v.pk);
        const eseed = hexToBytes(v.eseed);
        const ct = hexToBytes(v.ct);
        const ss = hexToBytes(v.ss);
        assertEquals(seed.length, 32);
        assertEquals(sk.length, 32);
        assertEquals(pk.length, 1216);
        assertEquals(eseed.length, 64);
        assertEquals(ct.length, 1120);
        assertEquals(ss.length, 32);

        const recipient = new XWing();
        const kp = await recipient.generateKeyPairDerand(seed);
        assertEquals(
          (await recipient.serializePublicKey(kp.publicKey)).byteLength,
          1216,
        );
        assertEquals(
          new Uint8Array(await recipient.serializePrivateKey(kp.privateKey)),
          sk,
        );
        assertEquals(
          new Uint8Array(await recipient.serializePublicKey(kp.publicKey)),
          pk,
        );
        const sender = new XWing();
        const res = await sender.encap({
          recipientPublicKey: kp.publicKey,
          ekm: eseed,
        });
        const ssR = await recipient.decap({
          enc: res.enc,
          recipientKey: kp.privateKey,
        });
        assertEquals(res.enc.byteLength, 1120);
        assertEquals(res.sharedSecret.byteLength, 32);
        assertEquals(res.enc, ct);
        assertEquals(res.sharedSecret, ssR);
        assertEquals(res.sharedSecret, ss);
        // assertEquals(ssR, ss);
      }
    });
  });

  describe("importKey", () => {
    it("with valid raw - as ArrayBuffer", async () => {
      const kem = new XWing();
      const pkR = await kem.importKey(
        "raw",
        hexToBytes(
          "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
        ).buffer,
        true,
      );
      const skR = await kem.importKey(
        "raw",
        hexToBytes(
          "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        ).buffer,
        false,
      );
      const res = await kem.encap({ recipientPublicKey: pkR });
      const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
      assertEquals(res.sharedSecret, ssR);
    });

    it("with valid raw - as Uint8Array", async () => {
      const kem = new XWing();
      const pkR = await kem.importKey(
        "raw",
        hexToBytes(
          "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
        ),
        true,
      );
      const skR = await kem.importKey(
        "raw",
        hexToBytes(
          "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        ),
        false,
      );
      const res = await kem.encap({ recipientPublicKey: pkR });
      const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
      assertEquals(res.sharedSecret, ssR);
    });

    it("with valid jwk", async () => {
      const kem = new XWing();

      const jwkPkR = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: [],
      };
      const pkR = await kem.importKey("jwk", jwkPkR, true);

      const jwkSkR = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: ["deriveBits"],
      };

      const skR = await kem.importKey("jwk", jwkSkR, false);
      const res = await kem.encap({ recipientPublicKey: pkR });
      const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
      assertEquals(res.sharedSecret, ssR);
    });

    it("with valid jwk - private key with pub", async () => {
      const kem = new XWing();

      const jwkPkR = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: [],
      };
      const pkR = await kem.importKey("jwk", jwkPkR, true);

      const jwkSkR = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: ["deriveBits"],
      };

      const skR = await kem.importKey("jwk", jwkSkR, false);
      const res = await kem.encap({ recipientPublicKey: pkR });
      const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
      assertEquals(res.sharedSecret, ssR);
    });

    it("with valid jwk - public key without key_ops", async () => {
      const kem = new XWing();

      const jwkPkR = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        // key_ops: [],
      };
      const pkR = await kem.importKey("jwk", jwkPkR, true);

      const jwkSkR = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: ["deriveBits"],
      };

      const skR = await kem.importKey("jwk", jwkSkR, false);
      const res = await kem.encap({ recipientPublicKey: pkR });
      const ssR = await kem.decap({ enc: res.enc, recipientKey: skR });
      assertEquals(res.sharedSecret, ssR);
    });

    it("with invalid raw - public key with valid jwk", async () => {
      const kem = new XWing();
      const jwkPkR = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
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
      const kem = new XWing();
      await assertRejects(
        () =>
          kem.importKey(
            "raw",
            hexToBytes(
              "236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
            ),
            true,
          ),
        DeserializeError,
      );
    });

    it("with invalid raw - private key with invalid length of the key", async () => {
      const kem = new XWing();
      await assertRejects(
        () =>
          kem.importKey(
            "raw",
            hexToBytes(
              "9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
            ),
            false,
          ),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with valid raw key", async () => {
      const kem = new XWing();
      await assertRejects(
        () =>
          kem.importKey(
            "jwk",
            hexToBytes(
              "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
            ),
            true,
          ),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with invalid kty", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "OKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key without kty", async () => {
      const kem = new XWing();

      const jwk = {
        // kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with invalid alg", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wind",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key without alg", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        // alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with invalid length of the key", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "NrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with priv", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key without pub", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        x: "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: [],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with invalid key_ops including deriveBits", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - public key with invalid key_ops including encrypt", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: ["encrypt"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key with invalid kty", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "OKP",
        kid: "01",
        alg: "X-Wing",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key without kty", async () => {
      const kem = new XWing();

      const jwk = {
        // kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key with invalid alg", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wind",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key without alg", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        // alg: "X-Wing",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key with invalid length of the key", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        priv: "wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, false),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key without priv", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        // priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: ["deriveBits"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key with invalid key_ops", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
        key_ops: ["encrypt"],
      };
      // assert
      await assertRejects(
        () => kem.importKey("jwk", jwk, true),
        DeserializeError,
      );
    });

    it("with invalid jwk - private key with invalid key_ops including a valid value", async () => {
      const kem = new XWing();

      const jwk = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
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
  describe("XWing/HkdfShar256/Aes256Gcm", () => {
    it("should work normally with generateKeyPair", async () => {
      const suite = new CipherSuite({
        kem: new XWing(),
        kdf: new HkdfSha256(),
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
        new TextEncoder().encode("my-secret-message"),
      );
      const pt = await recipient.open(ct);
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with deriveKeyPair", async () => {
      const suite = new CipherSuite({
        kem: new XWing(),
        kdf: new HkdfSha256(),
        aead: new Aes256Gcm(),
      });
      const cryptoApi = await loadCrypto();
      const ikm = new Uint8Array(32);
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
        new TextEncoder().encode("my-secret-message"),
      );
      const pt = await recipient.open(ct);
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with JWK", async () => {
      // const pub = bytesToBase64Url(
      //   hexToBytes(
      //     "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
      //   ),
      // );
      // console.log(pub);
      // const priv = bytesToBase64Url(
      //   hexToBytes(
      //     "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
      //   ),
      // );
      // console.log(priv);

      const suite = new CipherSuite({
        kem: new XWing(),
        kdf: new HkdfSha256(),
        aead: new Aes256Gcm(),
      });

      // NOTE: The following support for JWKs with the AKP key type is experimental.
      // Please be aware that the specifications are subject to change without notice.
      const jwkPub = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        pub:
          "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
        key_ops: [],
      };
      const pk = await suite.kem.importKey("jwk", jwkPub, true);
      const sender = await suite.createSenderContext({
        recipientPublicKey: pk,
      });

      const jwkPriv = {
        kty: "AKP",
        kid: "01",
        alg: "X-Wing",
        priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
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
