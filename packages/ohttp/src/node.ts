import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

/** Options of {@link toNodeListener}. */
export interface NodeListenerOptions {
  /**
   * Called with errors thrown by the handler or raised while its response is
   * written. Failures caused by the client disconnecting are not reported.
   */
  onError?: (error: unknown) => void;
}

/**
 * Adapt a Web Fetch handler, such as the one returned by `createOhttpHandler`,
 * to a `node:http` request listener.
 *
 * Request and response bodies are streamed. The request's signal is aborted
 * when the client disconnects before the response is complete. A handler
 * failure is answered with 500, or by closing the connection once the response
 * has started.
 */
export function toNodeListener(
  handler: (request: Request) => Response | Promise<Response>,
  options: NodeListenerOptions = {},
): (incoming: IncomingMessage, outgoing: ServerResponse) => Promise<void> {
  return async (incoming, outgoing) => {
    const controller = new AbortController();
    const onClose = () => {
      if (!outgoing.writableFinished) controller.abort();
    };
    outgoing.once("close", onClose);
    let streaming = false;
    try {
      let request: Request;
      try {
        request = toRequest(incoming, controller.signal);
      } catch {
        // The request line or headers do not form a valid Fetch request.
        outgoing.writeHead(400);
        outgoing.end();
        return;
      }
      const response = await handler(request);
      if (outgoing.destroyed) {
        void response.body?.cancel().catch(() => {});
        return;
      }
      outgoing.writeHead(
        response.status,
        response.statusText,
        toNodeHeaders(response.headers),
      );
      if (response.body && incoming.method === "HEAD") {
        // A HEAD response carries no content; do not wait for the body to end.
        // Cancellation may stay pending, so it must not delay the response.
        void response.body.cancel().catch(() => {});
        outgoing.end();
      } else if (response.body) {
        streaming = true;
        await pipeline(
          Readable.fromWeb(
            response.body as Parameters<typeof Readable.fromWeb>[0],
          ),
          outgoing,
        );
      } else {
        outgoing.end();
      }
    } catch (error) {
      // A body failure also closes the response, so a disconnect during
      // streaming is recognized by the error that pipeline() reports for it.
      const disconnected = streaming
        ? (error as { code?: unknown })?.code === "ERR_STREAM_PREMATURE_CLOSE"
        : controller.signal.aborted;
      try {
        if (!disconnected) options.onError?.(error);
      } finally {
        if (outgoing.headersSent) {
          outgoing.destroy();
        } else if (!outgoing.destroyed) {
          outgoing.writeHead(500);
          outgoing.end();
        }
      }
    } finally {
      outgoing.off("close", onClose);
    }
  };
}

function toRequest(incoming: IncomingMessage, signal: AbortSignal): Request {
  const scheme = (incoming.socket as { encrypted?: boolean }).encrypted
    ? "https"
    : "http";
  const headers = new Headers();
  for (let i = 0; i + 1 < incoming.rawHeaders.length; i += 2) {
    const name = incoming.rawHeaders[i];
    // HTTP/2 pseudo-header fields are not Fetch headers.
    if (!name.startsWith(":")) headers.append(name, incoming.rawHeaders[i + 1]);
  }
  const hasBody = incoming.method !== "GET" && incoming.method !== "HEAD";
  return new Request(
    `${scheme}://${incoming.headers.host ?? "localhost"}${incoming.url ?? "/"}`,
    {
      method: incoming.method,
      headers,
      signal,
      ...(hasBody
        ? {
          body: Readable.toWeb(incoming) as ReadableStream<Uint8Array>,
          duplex: "half",
        }
        : {}),
    } as RequestInit,
  );
}

function toNodeHeaders(headers: Headers): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  // Iteration combines repeated fields except Set-Cookie, which stays separate.
  headers.forEach((value, name) => {
    const current = result[name];
    if (current === undefined) result[name] = value;
    else if (Array.isArray(current)) current.push(value);
    else result[name] = [current, value];
  });
  return result;
}
