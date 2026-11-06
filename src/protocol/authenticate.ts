import type { Operation } from "./envelope.ts";
import { sessionIdOf } from "./envelope.ts";
import type { Claims, JwksCache } from "./jwt.ts";
import { kidOf, sha256Base64, verifyPlatformJwt } from "./jwt.ts";
import type { Store } from "./store.ts";

/**
 * The §6 preflight of every operation, in a load-bearing order:
 *
 *   SignatureAPI-Protocol header → JSON body → session id → bearer token → JWT (signature, iss,
 *   aud, exp, iat, jti not seen, operation, body_sha256) → connection token → token bound to the
 *   body's session → Content-Digest → spend the jti.
 *
 * The connection-token check sits after the JWT verifies (so a misaddressed token still answers
 * `unexpected aud`) and before the Idempotency-Key check that follows this function (so the
 * platform's key-less probe from an unlisted account sees 401, not 400). The `jti` is spent only
 * once everything passed, so a request refused at any step leaves it usable by a legitimate retry.
 */

export type AuthOptions = {
  jwks: JwksCache;
  issuer: string;
  publicUrl: string;
  connectionTokens: readonly string[];
  store: Store;
  now: () => number;
};

export type Authenticated = { sessionId: string; body: Record<string, unknown>; bodySha256: string; claims: Claims };
export type AuthRejection = { status: 400 | 401; error: "invalid_request" | "invalid_token"; description: string };

export const CONNECTION_TOKEN_NOT_ALLOWED = "connection token not allowed";

function invalidRequest(description: string): AuthRejection {
  return { status: 400, error: "invalid_request", description };
}

function invalidToken(description: string): AuthRejection {
  return { status: 401, error: "invalid_token", description };
}

function decodeBody(rawBody: Uint8Array): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(rawBody));
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export async function authenticate(
  headers: Headers,
  rawBody: Uint8Array,
  operation: Operation,
  options: AuthOptions,
): Promise<Authenticated | AuthRejection> {
  if (headers.get("signatureapi-protocol") !== "swp/1") {
    return invalidRequest("missing SignatureAPI-Protocol");
  }
  const body = decodeBody(rawBody);
  if (body === null) {
    return invalidRequest("body is not a JSON object");
  }
  const sessionId = sessionIdOf(body);
  if (sessionId === null) {
    return invalidRequest("session.id is missing or invalid");
  }
  const authorization = headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ")) {
    return invalidToken("missing bearer token");
  }
  const token = authorization.slice("Bearer ".length);
  // Throws only when no key set has ever been fetched: an outage, answered 503 by the caller.
  const keys = await options.jwks.keysFor(kidOf(token));
  const session = options.store.session(sessionId);
  const now = options.now();
  const verified = verifyPlatformJwt({
    token,
    rawBody,
    operation,
    issuer: options.issuer,
    audience: options.publicUrl,
    keys,
    now,
    isJtiSeen: (jti) => session.get(`jti:${jti}`) !== undefined,
  });
  if ("rejection" in verified) {
    return invalidToken(verified.rejection);
  }
  const connectionToken = verified.claims.connection_token;
  if (typeof connectionToken !== "string" || !options.connectionTokens.includes(connectionToken)) {
    return invalidToken(CONNECTION_TOKEN_NOT_ALLOWED);
  }
  // `body_sha256` already pins the envelope, but every store is keyed by session, so the token's
  // session is checked on its own: a token minted for one session never spends another's state.
  const swp = verified.claims.swp as Record<string, unknown>;
  if (swp.session !== sessionId) {
    return invalidToken("session mismatch");
  }
  const bodySha256 = sha256Base64(rawBody);
  if (headers.get("content-digest") !== `sha-256=:${bodySha256}:`) {
    return invalidRequest("Content-Digest mismatch");
  }
  session.put(`jti:${verified.jti}`, true, verified.jtiExpiresAt - now);
  return { sessionId, body, bodySha256, claims: verified.claims };
}
