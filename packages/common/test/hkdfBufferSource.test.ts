import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { HkdfSha256Native, toArrayBuffer, toUint8Array } from "../mod.ts";

describe("toArrayBuffer", () => {
  it("returns the same instance when input is ArrayBuffer", () => {
    const src = new Uint8Array([1, 2, 3, 4]).buffer;
    const out = toArrayBuffer(src);
    assertEquals(out === src, true);
  });

  it("copies only the visible range when input is an ArrayBufferView", () => {
    const src = new Uint8Array([10, 11, 12, 13]);
    const view = new Uint8Array(src.buffer, 1, 2);
    const out = toArrayBuffer(view);

    assertEquals(new Uint8Array(out), new Uint8Array([11, 12]));
    assertEquals(out === src.buffer, false);
  });
});

describe("toUint8Array", () => {
  it("returns a Uint8Array view over ArrayBuffer input", () => {
    const src = new Uint8Array([1, 2, 3]).buffer;
    const out = toUint8Array(src);

    out[0] = 9;
    assertEquals(new Uint8Array(src), new Uint8Array([9, 2, 3]));
  });

  it("creates a copied Uint8Array when input is an ArrayBufferView", () => {
    const src = new Uint8Array([20, 21, 22, 23]);
    const view = new Uint8Array(src.buffer, 1, 2);
    const out = toUint8Array(view);

    src[1] = 99;
    assertEquals(out, new Uint8Array([21, 22]));
    assertEquals(out.buffer === src.buffer, false);
  });
});

describe("HkdfSha256Native buffer-like inputs", () => {
  it("accepts ArrayBufferView and ArrayBufferLike for extract()", async () => {
    const kdf = new HkdfSha256Native();
    kdf.init(new Uint8Array([0, 1, 2, 3]));

    const ikm = new Uint8Array([1, 2, 3, 4]);
    const outFromView = await kdf.extract(
      new Uint8Array(0),
      new DataView(ikm.buffer),
    );
    const outFromArrayBuffer = await kdf.extract(
      new ArrayBuffer(0),
      ikm.buffer,
    );

    assertEquals(
      new Uint8Array(outFromView),
      new Uint8Array(outFromArrayBuffer),
    );
  });

  it("accepts ArrayBufferView inputs for extractAndExpand()", async () => {
    const kdf = new HkdfSha256Native();
    kdf.init(new Uint8Array([0, 1, 2, 3]));

    const saltSrc = new Uint8Array(40);
    const ikmSrc = new Uint8Array([100, 101, 102, 103, 104, 105]);
    const infoSrc = new Uint8Array([200, 201, 202, 203, 204]);

    const saltView = new Uint8Array(saltSrc.buffer, 4, 32);
    const ikmView = new Uint8Array(ikmSrc.buffer, 1, 4);
    const infoView = new Uint8Array(infoSrc.buffer, 1, 3);

    const outFromView = await kdf.extractAndExpand(
      saltView,
      ikmView,
      infoView,
      16,
    );
    const outFromArrayBuffer = await kdf.extractAndExpand(
      new Uint8Array(saltView).buffer,
      new Uint8Array(ikmView).buffer,
      new Uint8Array(infoView).buffer,
      16,
    );

    assertEquals(
      new Uint8Array(outFromView),
      new Uint8Array(outFromArrayBuffer),
    );
  });
});
