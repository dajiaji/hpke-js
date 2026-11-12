import { assertEquals, assertRejects } from "@std/assert";
import {
  Aes128Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";
import { createChunkedEncoding } from "../mod.ts";
import { collect } from "../src/streams.ts";
const encoding = createChunkedEncoding();

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
});
function hex(s: string): Uint8Array {
  return new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));
}

Deno.test("chunked draft-08 Appendix A request with byte-fragmented transport", async () => {
  const key = await suite.kem.importKey(
    "raw",
    hex("1c190d72acdbe4dbc69e680503bb781a932c70a12c8f3754434c67d8640d8698")
      .buffer as ArrayBuffer,
    false,
  );
  const wire = hex(
    "01002000010001" +
      "8811eb457e100811c40a0aa71340a1b81d804bb986f736f2f566a7199761a032" +
      "1c2ad24942d4d692563012f2980c8fef437a336b9b2fc938ef77a5834f" +
      "1d2e33d8fd25577afe31bd1c79d094f76b6250ae6549b473ecd950501311" +
      "001c6c1395d0ef7c1022297966307b8a7f",
  );
  const ctx = await encoding.decapsulateRequest(
    suite,
    1,
    key,
    Array.from(wire, (b) => new Uint8Array([b])),
  );
  assertEquals(
    await collect(ctx.body),
    hex("00034745540568747470730b6578616d706c652e636f6d012f"),
  );
});

Deno.test("chunked request/response, size splitting, empty final and tampering", async () => {
  const keys = await suite.kem.generateKeyPair();
  const data = new Uint8Array(40000).fill(42);
  const client = await encoding.encapsulateRequest(suite, 1, keys.publicKey, [
    data,
    new Uint8Array(0),
  ]);
  const wire = await collect(client.body);
  const server = await encoding.decapsulateRequest(suite, 1, keys.privateKey, [
    wire,
  ]);
  assertEquals(await collect(server.body), data);
  const response = await collect(
    (await server.encapsulateResponse([data])).body,
  );
  assertEquals(
    await collect(await client.decapsulateResponse([response])),
    data,
  );
  await assertRejects(async () =>
    collect(await client.decapsulateResponse([response]))
  );

  for (const bad of [wire.slice(0, -1), wire.slice(0, -17), wire.slice()]) {
    if (bad.length === wire.length) bad[bad.length - 1] ^= 1;
    const ctx = await encoding.decapsulateRequest(suite, 1, keys.privateKey, [
      bad,
    ]);
    await assertRejects(() => collect(ctx.body));
  }
});

Deno.test("non-minimal QUIC lengths, nonempty final, empty non-final rejection", async () => {
  const keys = await suite.kem.generateKeyPair();
  const header = new Uint8Array([1, 0, 32, 0, 1, 0, 1]);
  const label = new TextEncoder().encode("message/bhttp chunked request\0");
  const info = new Uint8Array(label.length + header.length);
  info.set(label);
  info.set(header, label.length);
  for (const empty of [false, true]) {
    const sender = await suite.createSenderContext({
      recipientPublicKey: keys.publicKey,
      info,
    });
    const first = new Uint8Array(
      await sender.seal(new Uint8Array(empty ? [] : [7])),
    );
    const final = new Uint8Array(
      await sender.seal(new Uint8Array([8]), new TextEncoder().encode("final")),
    );
    const wire = [
      header,
      new Uint8Array(sender.enc),
      new Uint8Array([0x40, first.length]),
      first,
      new Uint8Array([0x40, 0]),
      final,
    ];
    const server = await encoding.decapsulateRequest(
      suite,
      1,
      keys.privateKey,
      wire,
    );
    if (empty) await assertRejects(() => collect(server.body));
    else assertEquals(await collect(server.body), new Uint8Array([7, 8]));
  }
});

Deno.test("chunk size limits reject declared and final oversize before EOF", async () => {
  const keys = await suite.kem.generateKeyPair();
  const sent = await encoding.encapsulateRequest(suite, 1, keys.publicKey, []);
  const header = (await collect(sent.body)).slice(0, 7 + suite.kem.encSize);
  const { concat, encodeInteger } = await import("../src/streams.ts");
  for (const final of [false, true]) {
    let cancelled = false;
    const wire = concat([
      header,
      final ? new Uint8Array(1) : encodeInteger(16385 + suite.aead.tagSize),
      ...(final ? [new Uint8Array(16385 + suite.aead.tagSize)] : []),
    ]);
    const transport = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(wire);
      },
      cancel() {
        cancelled = true;
      },
    });
    const received = await encoding.decapsulateRequest(
      suite,
      1,
      keys.privateKey,
      transport,
    );
    await assertRejects(() => collect(received.body), Error, "size limit");
    assertEquals(cancelled, true);
  }
});

Deno.test("receiver can explicitly accept final chunks larger than 16 KiB", async () => {
  const keys = await suite.kem.generateKeyPair();
  const header = new Uint8Array([1, 0, 32, 0, 1, 0, 1]);
  const { concat } = await import("../src/streams.ts");
  const sender = await suite.createSenderContext({
    recipientPublicKey: keys.publicKey,
    info: concat([
      new TextEncoder().encode("message/bhttp chunked request\0"),
      header,
    ]),
  });
  const data = new Uint8Array(20000).fill(7);
  const final = new Uint8Array(
    await sender.seal(data, new TextEncoder().encode("final")),
  );
  const received = await createChunkedEncoding({ maxChunkSize: 32768 })
    .decapsulateRequest(
      suite,
      1,
      keys.privateKey,
      [header, new Uint8Array(sender.enc), new Uint8Array(1), final],
    );
  assertEquals(await collect(received.body), data);
});
