import { HpkeError } from "@hpke/common";

import type { OhttpClient } from "./client.ts";
import type { OhttpGateway } from "./server.ts";
import {
  decodeRequest,
  decodeResponse,
  encodeRequest,
  encodeResponse,
} from "./bhttp.ts";
import { ByteReader, collect, stream } from "./streams.ts";
import { OhttpError } from "./errors.ts";

function mediaType(value: string | null): string {
  return value?.split(";")[0].trim().toLowerCase() ?? "";
}

/**
 * Fetch a target through the client's relay. input/init describe the target.
 * Streaming uploads require a runtime/relay that supports streaming fetch bodies.
 */
export async function ohttpFetch(
  client: OhttpClient,
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  if (!client.relayUrl) {
    throw new OhttpError("relayUrl is required by ohttpFetch");
  }
  const request = new Request(input, init);
  request.signal.throwIfAborted();
  const exchange = await client.encapsulateRequest(
    withSignal(encodeRequest(request), request.signal),
  );
  const headers = new Headers({
    "Content-Type": exchange.contentType,
    "Accept": client.encoding.responseContentType,
  });
  if (client.encoding.incremental) headers.set("Incremental", "?1");
  const streaming = client.encoding.incremental && client.streamingUpload &&
    request.body !== null;
  const body = streaming
    ? exchange.body
    : (await collect(exchange.body)).buffer as ArrayBuffer;
  let response: Response;
  try {
    response = await fetch(client.relayUrl, {
      method: "POST",
      headers,
      body,
      signal: request.signal,
      redirect: "error",
      ...(streaming ? { duplex: "half" } : {}),
    } as RequestInit);
  } catch (error) {
    if (!exchange.body.locked) await exchange.body.cancel().catch(() => {});
    throw error;
  }
  if (
    !response.ok ||
    mediaType(response.headers.get("Content-Type")) !==
      client.encoding.responseContentType ||
    !response.body
  ) {
    await response.body?.cancel();
    throw new OhttpError(
      !response.ok
        ? `Relay returned HTTP ${response.status}`
        : "Unexpected OHTTP response content type or missing body",
    );
  }
  return decodeResponse(
    withSignal(
      await exchange.decapsulateResponse(
        withSignal(response.body, request.signal),
      ),
      request.signal,
    ),
    request.method,
  );
}

/** HTTP gateway adapter parameters. The application controls target authorization. */
export interface OhttpGatewayHandlerParams {
  gateway: OhttpGateway;
  /** Return headers that describe the body bytes. Native fetch may decompress
   * a response while retaining Content-Encoding/Content-Length; normalize those
   * headers before returning its decoded body, or use
   * {@link createOhttpFetchForwarder}.
   */
  forward(request: Request): Promise<Response>;
}

/** Adapt an explicitly configured gateway to a Web Fetch request handler. */
export function createOhttpGatewayHandler(
  params: OhttpGatewayHandlerParams,
): (request: Request) => Promise<Response> {
  const { gateway, forward } = params;
  return async (outer) => {
    if (outer.method !== "POST") {
      void outer.body?.cancel().catch(() => {});
      return new Response(null, { status: 405, headers: { Allow: "POST" } });
    }
    if (
      mediaType(outer.headers.get("Content-Type")) !==
        gateway.encoding.requestContentType || !outer.body
    ) {
      return new Response(null, { status: 415 });
    }
    let exchange;
    let request: Request;
    let inputFailure: unknown;
    try {
      exchange = await gateway.decapsulateRequest(outer.body);
      const input = new ByteReader(exchange.body);
      const tracked = stream(
        (async function* () {
          try {
            yield* input.rest();
          } catch (error) {
            inputFailure = error;
            throw error;
          }
        })(),
        () => input.close(),
      );
      request = await decodeRequest(tracked, (error) => {
        inputFailure = error;
      });
    } catch (error) {
      if (!outer.body.locked) await outer.body.cancel().catch(() => {});
      if (isInputError(error)) return new Response(null, { status: 400 });
      throw error;
    }
    let response: Response;
    try {
      response = await forward(request);
    } catch (error) {
      if (request.body && !request.body.locked) {
        await request.body.cancel().catch(() => {});
      }
      // Input body errors may surface through forward() (for example fetch).
      // An independent upstream/network error must retain its server-error semantics.
      if (inputFailure !== undefined && isInputError(inputFailure)) {
        return new Response(null, { status: 400 });
      }
      throw error;
    }
    let encoded: ReadableStream<Uint8Array> | undefined;
    let encrypted;
    try {
      encoded = encodeResponse(response);
      encrypted = await exchange.encapsulateResponse(encoded);
    } catch (error) {
      if (encoded && !encoded.locked) await encoded.cancel().catch(() => {});
      if (response.body && !response.body.locked) {
        await response.body.cancel().catch(() => {});
      }
      throw error;
    }
    const headers = new Headers({ "Content-Type": encrypted.contentType });
    if (gateway.encoding.incremental) headers.set("Incremental", "?1");
    return new Response(encrypted.body, { headers });
  };
}

/**
 * Create a Web Fetch handler that serves the gateway's key configuration as
 * `application/ohttp-keys`. It is independent of {@link createOhttpGatewayHandler}:
 * mount it wherever the deployment publishes key configurations.
 */
export function createOhttpKeyConfigHandler(
  gateway: OhttpGateway,
): (request: Request) => Promise<Response> {
  return async (request) => {
    if (request.method !== "GET" && request.method !== "HEAD") {
      void request.body?.cancel().catch(() => {});
      return new Response(null, {
        status: 405,
        headers: { Allow: "GET, HEAD" },
      });
    }
    const keyConfig = new Uint8Array(await gateway.publicKeyConfig);
    return new Response(request.method === "HEAD" ? null : keyConfig.buffer, {
      headers: {
        "Content-Type": "application/ohttp-keys",
        "Content-Length": String(keyConfig.length),
      },
    });
  };
}

/** Parameters of a `forward` callback that fetches allowed targets. */
export interface OhttpFetchForwarderParams {
  /** Origins (for example `https://target.example`) the gateway may reach. */
  allowedOrigins: Iterable<string | URL>;
  /** The fetch implementation used to reach targets. Defaults to `fetch`. */
  fetch?: (request: Request, init?: RequestInit) => Promise<Response>;
}

/**
 * Create a `forward` callback for {@link createOhttpGatewayHandler} that fetches the
 * target request. Requests to origins outside `allowedOrigins` are answered
 * with 403 without being sent. Redirects are returned to the client instead
 * of being followed, so they cannot leave the allowed origins. Content-Encoding
 * and Content-Length are removed from responses with a body, because fetch
 * returns the decoded body while retaining those headers.
 */
export function createOhttpFetchForwarder(
  params: OhttpFetchForwarderParams,
): (request: Request) => Promise<Response> {
  const origins = new Set<string>();
  for (const value of params.allowedOrigins) {
    const origin = new URL(value).origin;
    if (origin === "null") {
      throw new OhttpError(`Invalid allowed origin: ${value}`);
    }
    origins.add(origin);
  }
  const fetchTarget = params.fetch ?? ((request, init) => fetch(request, init));
  return async (request) => {
    if (!origins.has(new URL(request.url).origin)) {
      if (request.body) await request.body.cancel().catch(() => {});
      return new Response(null, { status: 403 });
    }
    const response = await fetchTarget(request, { redirect: "manual" });
    if (!response.body) return response;
    const headers = new Headers(response.headers);
    headers.delete("content-encoding");
    headers.delete("content-length");
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  };
}

/** Parameters of a relay handler. */
export interface OhttpRelayHandlerParams {
  /** The gateway resource that encapsulated requests are forwarded to. */
  gatewayUrl: string | URL;
  /**
   * Stream request bodies to the gateway instead of buffering them. Requires a
   * runtime and a gateway connection that support streaming fetch bodies.
   */
  streamingUpload?: boolean;
  /** The fetch implementation used to reach the gateway. Defaults to `fetch`. */
  fetch?: (request: Request, init?: RequestInit) => Promise<Response>;
}

const RELAY_REQUEST_TYPES = new Set([
  "message/ohttp-req",
  "message/ohttp-chunked-req",
]);
const RELAY_HEADERS = ["Content-Type", "Incremental"];

/**
 * Create a Web Fetch handler for an Oblivious Relay Resource. It forwards
 * encapsulated requests to the configured gateway and returns its response,
 * without decrypting either.
 *
 * Only the Content-Type and Incremental fields are forwarded in each direction,
 * so that client fields such as cookies, credentials or forwarding information
 * do not reach the gateway. Redirects from the gateway are not followed, and a
 * failure to reach the gateway is thrown to the caller.
 */
export function createOhttpRelayHandler(
  params: OhttpRelayHandlerParams,
): (request: Request) => Promise<Response> {
  const gatewayUrl = new URL(params.gatewayUrl).href;
  const streaming = params.streamingUpload ?? false;
  const fetchGateway = params.fetch ??
    ((request, init) => fetch(request, init));
  return async (request) => {
    if (request.method !== "POST") {
      void request.body?.cancel().catch(() => {});
      return new Response(null, { status: 405, headers: { Allow: "POST" } });
    }
    if (
      !RELAY_REQUEST_TYPES.has(
        mediaType(request.headers.get("Content-Type")),
      ) || !request.body
    ) {
      void request.body?.cancel().catch(() => {});
      return new Response(null, { status: 415 });
    }
    const response = await fetchGateway(
      new Request(
        gatewayUrl,
        {
          method: "POST",
          headers: relayHeaders(request.headers),
          body: streaming ? request.body : await request.arrayBuffer(),
          signal: request.signal,
          redirect: "error",
          ...(streaming ? { duplex: "half" } : {}),
        } as RequestInit,
      ),
    );
    return new Response(response.body, {
      status: response.status,
      headers: relayHeaders(response.headers),
    });
  };
}

function relayHeaders(source: Headers): Headers {
  const headers = new Headers();
  for (const name of RELAY_HEADERS) {
    const value = source.get(name);
    if (value !== null) headers.set(name, value);
  }
  return headers;
}

// Bind both buffered encoding and lazy decoding to the target request's signal.
function withSignal(
  source: ReadableStream<Uint8Array>,
  signal: AbortSignal,
): ReadableStream<Uint8Array> {
  const reader = source.getReader();
  let closed = false;
  let controller: ReadableStreamDefaultController<Uint8Array>;
  async function close(cancel: boolean): Promise<void> {
    if (closed) return;
    closed = true;
    signal.removeEventListener("abort", abort);
    try {
      if (cancel) await reader.cancel(signal.reason);
    } finally {
      reader.releaseLock();
    }
  }
  function abort(): void {
    controller.error(signal.reason);
    void close(true).catch(() => {});
  }
  return new ReadableStream({
    start(value) {
      controller = value;
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    },
    async pull() {
      try {
        const next = await reader.read();
        if (closed) return;
        if (next.done) {
          controller.close();
          await close(false);
        } else controller.enqueue(next.value);
      } catch (error) {
        if (!closed) controller.error(error);
        await close(true);
      }
    },
    cancel() {
      return close(true);
    },
  }, { highWaterMark: 0 });
}

function isInputError(error: unknown): boolean {
  return error instanceof OhttpError || error instanceof HpkeError ||
    (error instanceof DOMException && error.name === "OperationError");
}
