import { decodeBase64Url } from "./utils.ts";
import { JoseError } from "./errors.ts";

const te = new TextEncoder();

/** A recipient entry of a JWE General JSON Serialization, as accepted by open(). */
export interface JweGeneralRecipientJson {
  header?: Record<string, unknown>;
  encrypted_key?: string;
}

/** JWE General JSON Serialization, as accepted by open(). */
export interface JweGeneralJson {
  protected: string;
  unprotected?: Record<string, unknown>;
  iv?: string;
  aad?: string;
  ciphertext: string;
  tag?: string;
  recipients: JweGeneralRecipientJson[];
}

/** JWE Flattened JSON Serialization, as accepted by open(). */
export interface JweFlattenedJson {
  protected: string;
  unprotected?: Record<string, unknown>;
  header?: Record<string, unknown>;
  encrypted_key?: string;
  iv?: string;
  aad?: string;
  ciphertext: string;
  tag?: string;
}

/** A recipient entry of the JWE produced by JoseEncrypt.seal(). */
export interface JweRecipientJson extends JweGeneralRecipientJson {
  header: Record<string, unknown>;
  encrypted_key: string;
}

/** The JWE General JSON Serialization produced by JoseEncrypt.seal(). */
export interface JweJson extends JweGeneralJson {
  iv: string;
  tag: string;
  recipients: JweRecipientJson[];
}

/** @internal */
export interface ParsedRecipient {
  /** The union of the protected, shared and per-recipient headers. */
  joseHeader: Record<string, unknown>;
  encryptedKey: string;
}

/** @internal */
export interface ParsedJwe {
  protectedHeader: Record<string, unknown>;
  /** The Additional Authenticated Data encryption parameter. */
  additionalData: Uint8Array;
  iv: string;
  ciphertext: string;
  tag: string;
  recipients: ParsedRecipient[];
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseProtectedHeader(encoded: string): Record<string, unknown> {
  let header: unknown;
  try {
    header = JSON.parse(new TextDecoder().decode(decodeBase64Url(encoded)));
  } catch {
    throw new JoseError("Invalid protected header");
  }
  if (!isJsonObject(header)) {
    throw new JoseError("Invalid protected header");
  }
  return header;
}

/** Build the JOSE Header, rejecting names that occur in more than one part. */
function buildJoseHeader(
  ...parts: (Record<string, unknown> | undefined)[]
): Record<string, unknown> {
  // No prototype: "__proto__" in a header must stay an ordinary name.
  const joseHeader: Record<string, unknown> = Object.create(null);
  for (const part of parts) {
    if (part === undefined) continue;
    if (!isJsonObject(part)) {
      throw new JoseError("Invalid JOSE Header");
    }
    for (const [name, value] of Object.entries(part)) {
      if (Object.prototype.hasOwnProperty.call(joseHeader, name)) {
        throw new JoseError(`Duplicate Header Parameter: ${name}`);
      }
      joseHeader[name] = value;
    }
  }
  return joseHeader;
}

function parseCompact(jwe: string): ParsedJwe {
  const parts = jwe.split(".");
  if (parts.length !== 5) {
    throw new JoseError("Invalid JWE Compact Serialization");
  }
  const [encodedHeader, encryptedKey, iv, ciphertext, tag] = parts;
  if (!encodedHeader || !encryptedKey) {
    throw new JoseError("Invalid JWE Compact Serialization");
  }
  const protectedHeader = parseProtectedHeader(encodedHeader);
  return {
    protectedHeader,
    additionalData: te.encode(encodedHeader),
    iv,
    ciphertext,
    tag,
    recipients: [{
      joseHeader: buildJoseHeader(protectedHeader),
      encryptedKey,
    }],
  };
}

function parseJson(jwe: JweFlattenedJson | JweGeneralJson): ParsedJwe {
  if (!jwe.protected) {
    throw new JoseError("Missing protected header");
  }
  const protectedHeader = parseProtectedHeader(jwe.protected);

  let recipients: JweGeneralRecipientJson[];
  if ("recipients" in jwe) {
    if (!Array.isArray(jwe.recipients)) {
      throw new JoseError("Missing or invalid recipients array");
    }
    if ("header" in jwe || "encrypted_key" in jwe) {
      throw new JoseError(
        "recipients must not be used with header or encrypted_key",
      );
    }
    recipients = jwe.recipients;
  } else {
    recipients = [{ header: jwe.header, encrypted_key: jwe.encrypted_key }];
  }

  if (typeof jwe.ciphertext !== "string") {
    throw new JoseError("Missing ciphertext");
  }

  return {
    protectedHeader,
    additionalData: te.encode(
      jwe.aad !== undefined ? `${jwe.protected}.${jwe.aad}` : jwe.protected,
    ),
    iv: jwe.iv ?? "",
    ciphertext: jwe.ciphertext,
    tag: jwe.tag ?? "",
    recipients: recipients.map((entry) => {
      if (!isJsonObject(entry as unknown)) {
        throw new JoseError("Invalid recipient");
      }
      return {
        joseHeader: buildJoseHeader(
          protectedHeader,
          jwe.unprotected,
          entry.header,
        ),
        encryptedKey: entry.encrypted_key ?? "",
      };
    }),
  };
}

/**
 * Parse a JWE in any serialization into the values used by the message
 * decryption process of draft-ietf-jose-hpke-encrypt-22 Section 7.2.
 *
 * @internal
 */
export function parseJwe(
  jwe: string | JweFlattenedJson | JweGeneralJson,
): ParsedJwe {
  return typeof jwe === "string" ? parseCompact(jwe) : parseJson(jwe);
}
