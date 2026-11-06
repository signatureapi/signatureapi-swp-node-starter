import { createHash, createPublicKey, verify } from "node:crypto";

/**
 * Platform JWT verification (SWP/1 §6) and the platform key set it verifies against.
 *
 * Every operation carries `Authorization: Bearer <JWT>` minted by SignatureAPI per HTTP attempt:
 * ES256, `iss` = the platform, `aud` = this worker's exact public URL, a 5-minute `iat`/`exp`
 * window, a unique `jti`, and `swp: { session, operation, body_sha256 }` binding the token to the
 * exact body bytes. The worker pins the algorithm and checks all of it.
 */

export type PlatformJwk = { kty: "EC"; crv: "P-256"; x: string; y: string; kid: string };
export type Claims = Record<string, unknown>;

/** §6 acceptance window; also the floor for how long a spent `jti` is remembered. */
export const JTI_TTL_MS = 300_000;
/** Tolerated clock skew between the platform and the worker. */
export const CLOCK_SKEW_SECONDS = 60;

export function sha256Base64(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("base64");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeSegment(segment: string): Claims | null {
  try {
    const decoded: unknown = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    return isRecord(decoded) ? decoded : null;
  } catch {
    return null;
  }
}

function isPlatformJwk(value: unknown): value is PlatformJwk {
  return (
    isRecord(value) &&
    value.kty === "EC" &&
    value.crv === "P-256" &&
    typeof value.x === "string" &&
    typeof value.y === "string" &&
    typeof value.kid === "string"
  );
}

/**
 * The platform's key set, cached for five minutes (the platform serves it with `max-age=300`).
 * An empty set is a failure, never cached: the platform serves `keys: []` before its key exists.
 * A stale set outlives a failed refresh, so a platform blip does not turn every request into a 401.
 * With no set at all, a failure is remembered for up to 30 s so a down platform is not fetched once
 * per inbound request. An unknown `kid` (read off an unverified header, so attacker-controlled)
 * triggers at most one refetch per TTL window, enough to pick up a rotated key.
 */
export class JwksCache {
  private cached: { keys: PlatformJwk[]; at: number } | null = null;
  private failure: { at: number; message: string } | null = null;
  private rotationRefreshAt: number | null = null;
  private readonly url: string;
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;
  private readonly ttlMs: number;

  constructor(url: string, fetchFn: typeof fetch = fetch, now: () => number = Date.now, ttlMs = 300_000) {
    this.url = url;
    this.fetchFn = fetchFn;
    this.now = now;
    this.ttlMs = ttlMs;
  }

  async keysFor(kid: string): Promise<PlatformJwk[]> {
    const keys = await this.keys();
    if (keys.some((key) => key.kid === kid)) {
      return keys;
    }
    if (this.rotationRefreshAt !== null && this.now() - this.rotationRefreshAt < this.ttlMs) {
      return keys;
    }
    this.rotationRefreshAt = this.now();
    return this.refresh().catch(() => keys);
  }

  private async keys(): Promise<PlatformJwk[]> {
    if (this.cached && this.now() - this.cached.at < this.ttlMs) {
      return this.cached.keys;
    }
    if (!this.cached && this.failure && this.now() - this.failure.at < Math.min(this.ttlMs, 30_000)) {
      throw new Error(this.failure.message);
    }
    try {
      return await this.refresh();
    } catch (error) {
      if (this.cached) {
        return this.cached.keys;
      }
      this.failure = { at: this.now(), message: error instanceof Error ? error.message : "JWKS unavailable" };
      throw error;
    }
  }

  private async refresh(): Promise<PlatformJwk[]> {
    const response = await this.fetchFn(this.url, { headers: { accept: "application/json" } });
    if (!response.ok) {
      throw new Error(`JWKS ${this.url} answered ${response.status}`);
    }
    const body: unknown = await response.json();
    const keys = isRecord(body) && Array.isArray(body.keys) ? body.keys.filter(isPlatformJwk) : [];
    if (keys.length === 0) {
      throw new Error(`JWKS ${this.url} published no P-256 keys`);
    }
    this.cached = { keys, at: this.now() };
    this.failure = null;
    return keys;
  }
}

/** The `kid` off the unverified header, for the key lookup only. `verifyPlatformJwt` re-reads it. */
export function kidOf(token: string): string {
  const header = decodeSegment(token.split(".")[0] ?? "");
  return typeof header?.kid === "string" ? header.kid : "";
}

export type JwtCheck = {
  token: string;
  rawBody: Uint8Array;
  operation: string;
  issuer: string;
  audience: string;
  keys: PlatformJwk[];
  now: number;
  isJtiSeen: (jti: string) => boolean;
};

/** Accepted: the claims, the `jti` and how long to remember it. The caller spends the `jti` last. */
export type JwtResult = { claims: Claims; jti: string; jtiExpiresAt: number } | { rejection: string };

function signatureVerifies(jwk: PlatformJwk, signingInput: string, signature: Buffer): boolean {
  try {
    // Only the defining fields are imported: a field the platform adds later must not change the key.
    const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: "jwk" });
    // JOSE ES256 signatures are the raw 64-byte `r || s` pair.
    return verify("sha256", Buffer.from(signingInput), { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
}

/** The §6 check. The header is attacker-supplied: `alg` is pinned before anything else is read. */
export function verifyPlatformJwt(check: JwtCheck): JwtResult {
  const segments = check.token.split(".");
  if (segments.length !== 3) {
    return { rejection: "malformed token" };
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments as [string, string, string];
  const header = decodeSegment(headerSegment);
  if (header?.alg !== "ES256") {
    return { rejection: "alg must be ES256" };
  }
  const jwk = typeof header.kid === "string" ? check.keys.find((key) => key.kid === header.kid) : undefined;
  if (!jwk) {
    return { rejection: "unknown kid" };
  }
  if (!signatureVerifies(jwk, `${headerSegment}.${payloadSegment}`, Buffer.from(signatureSegment, "base64url"))) {
    return { rejection: "signature does not verify" };
  }
  const claims = decodeSegment(payloadSegment);
  if (claims === null) {
    return { rejection: "payload is not an object" };
  }
  if (claims.iss !== check.issuer) {
    return { rejection: "unexpected iss" };
  }
  if (claims.aud !== check.audience) {
    return { rejection: "unexpected aud" };
  }
  const nowSeconds = Math.floor(check.now / 1000);
  if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_SECONDS <= nowSeconds) {
    return { rejection: "token expired" };
  }
  if (typeof claims.iat !== "number" || claims.iat - CLOCK_SKEW_SECONDS > nowSeconds) {
    return { rejection: "token issued in the future" };
  }
  const jti = claims.jti;
  if (typeof jti !== "string" || jti.length === 0) {
    return { rejection: "missing jti" };
  }
  if (check.isJtiSeen(jti)) {
    return { rejection: "replayed jti" };
  }
  const swp = isRecord(claims.swp) ? claims.swp : {};
  if (swp.operation !== check.operation) {
    return { rejection: "operation mismatch" };
  }
  if (swp.body_sha256 !== sha256Base64(check.rawBody)) {
    return { rejection: "body_sha256 mismatch" };
  }
  // Remembered for as long as the token could still pass the exp check, never less than the window.
  const jtiExpiresAt = Math.max(check.now + JTI_TTL_MS, (claims.exp + CLOCK_SKEW_SECONDS) * 1000);
  return { claims, jti, jtiExpiresAt };
}
