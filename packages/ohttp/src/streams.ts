import { OhttpError } from "./errors.ts";

/** Binary fragments accepted by the low-level OHTTP API. */
export type OhttpSource =
  | ReadableStream<Uint8Array>
  | AsyncIterable<Uint8Array>
  | Iterable<Uint8Array>;

/** Adapt Web Streams with cancellation and lock release. */
export async function* fragments(
  source: OhttpSource,
): AsyncGenerator<Uint8Array> {
  if (!(source instanceof ReadableStream)) {
    for await (const part of source) yield part;
    return;
  }
  const reader = source.getReader();
  let done = false;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) {
        done = true;
        return;
      }
      yield next.value;
    }
  } finally {
    try {
      if (!done) await reader.cancel();
    } finally {
      reader.releaseLock();
    }
  }
}

export function stream(
  source: AsyncIterable<Uint8Array>,
  cleanup?: () => Promise<void>,
): ReadableStream<Uint8Array> {
  const iterator = source[Symbol.asyncIterator]();
  let stopped = false;
  // AsyncGenerator.return() queues behind an in-flight next(). Cleanup must
  // independently interrupt the owned reader before generator finalization.
  function finishIterator(): void {
    void iterator.return?.().catch(() => {});
  }
  return new ReadableStream({
    async pull(controller) {
      try {
        const next = await iterator.next();
        if (stopped) return;
        if (next.done) {
          stopped = true;
          controller.close();
        } else controller.enqueue(next.value);
      } catch (error) {
        if (stopped) return;
        stopped = true;
        controller.error(error);
        try {
          await cleanup?.();
        } finally {
          finishIterator();
        }
      }
    },
    async cancel() {
      stopped = true;
      try {
        await cleanup?.();
      } finally {
        finishIterator();
      }
    },
  }, { highWaterMark: 0 });
}

export function concat(parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export async function collect(source: OhttpSource): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const part of fragments(source)) parts.push(part);
  return concat(parts);
}

export function encodeInteger(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new OhttpError("Invalid integer");
  }
  const size = n < 64 ? 1 : n < 16384 ? 2 : n < 1073741824 ? 4 : 8;
  const bytes = new Uint8Array(size);
  let value = BigInt(n);
  for (let i = size - 1; i >= 0; --i) {
    bytes[i] = Number(value & 255n);
    value >>= 8n;
  }
  bytes[0] |= Math.log2(size) << 6;
  return bytes;
}

export class ByteReader {
  position = 0;
  private iterator?: AsyncIterator<Uint8Array>;
  private reader?: ReadableStreamDefaultReader<Uint8Array>;
  private closed = false;
  private pending: Uint8Array = new Uint8Array();
  constructor(source: OhttpSource) {
    if (source instanceof ReadableStream) {
      this.reader = source.getReader();
    } else if (Symbol.asyncIterator in source) {
      this.iterator = source[Symbol.asyncIterator]();
    } else {
      this.iterator = (async function* () {
        yield* source;
      })();
    }
  }
  async piece(max: number): Promise<Uint8Array> {
    while (!this.pending.length) {
      if (this.closed) return new Uint8Array();
      const next = this.reader
        ? await this.reader.read()
        : await this.iterator!.next();
      if (this.closed) return new Uint8Array();
      if (next.done) {
        await this.close();
        return new Uint8Array();
      }
      this.pending = next.value;
    }
    const part = this.pending.subarray(0, max);
    this.pending = this.pending.subarray(part.length);
    this.position += part.length;
    return part;
  }
  async read(size: number): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];
    while (size) {
      const part = await this.piece(size);
      if (!part.length) throw new OhttpError("Truncated message");
      parts.push(part);
      size -= part.length;
    }
    return concat(parts);
  }
  async integer(optional = false): Promise<number | undefined> {
    const first = await this.piece(1);
    if (!first.length) {
      if (optional) return undefined;
      throw new OhttpError("Truncated integer");
    }
    let n = BigInt(first[0] & 63);
    for (const b of await this.read((1 << (first[0] >> 6)) - 1)) {
      n = (n << 8n) | BigInt(b);
    }
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new OhttpError("Integer too large");
    }
    return Number(n);
  }
  async *rest(): AsyncGenerator<Uint8Array> {
    try {
      for (;;) {
        const part = await this.piece(16384);
        if (!part.length) return;
        yield part;
      }
    } finally {
      await this.close();
    }
  }
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.pending = new Uint8Array();
    if (this.reader) {
      try {
        await this.reader.cancel();
      } finally {
        this.reader.releaseLock();
      }
    } else {
      // An arbitrary async iterator may have an uninterruptible next().
      void this.iterator?.return?.().catch(() => {});
    }
  }
}
