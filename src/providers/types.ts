/**
 * The provider contract. A provider is a strategy: it implements the three SWP/1 operations for one
 * signing rail and, optionally, the browser pages its interactive legs send the signer to. Everything
 * else (request authentication, idempotency, the single-use authorization, tickets and codes) lives
 * in `src/protocol` and reaches the provider through the context it is handed.
 */

/** OIDs a provider is likely to compare against. */
export const OID = {
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  ecdsaWithSha256: "1.2.840.10045.4.3.2",
  ecPublicKey: "1.2.840.10045.2.1",
  sha256WithRsa: "1.2.840.113549.1.1.11",
} as const;

export type SignatureFormat = "raw" | "cms";

export type Signer = { id: string; name: string; email: string };

/** One digest as the platform sent it: `value` is the wire base64, `bytes` the decoded value. */
export type Digest = { value: string; bytes: Uint8Array; hashAlgorithmOid: string; label?: string };

/** The validated request, camelCase. The wire is snake_case; `src/protocol/envelope.ts` maps it. */
export type CredentialRequest = {
  session: { id: string; attempt: number };
  scheme: string;
  signer: Signer;
  callbackUrl: string;
  /** Present on the resume leg, after the signer's browser came back through `callbackUrl`. */
  callbackCode?: string;
};
export type AuthorizeRequest = CredentialRequest & { credentialId: string; digests: Digest[] };
export type SignRequest = CredentialRequest & {
  credentialId: string;
  digests: Digest[];
  authorizationReference: string;
  signatureFormat: SignatureFormat;
  /** Always present for `raw`; for `cms` only when the credential declared certificates and key algorithms. */
  signAlgoOid?: string;
};

// ---------------------------------------------------------------------------------------------
// Guards: everything read back from storage is validated on read. A row that fails its guard reads
// as "not stored", so a stale or corrupt row degrades to a protocol failure, never a crash.
// ---------------------------------------------------------------------------------------------

export type Guard<T> = (value: unknown) => value is T;
type Shape = Record<string, Guard<unknown>>;
type ShapeOf<S extends Shape> = { [K in keyof S]: S[K] extends Guard<infer T> ? T : never };

export const is = {
  string: ((value: unknown) => typeof value === "string") as Guard<string>,
  number: ((value: unknown) => typeof value === "number" && Number.isFinite(value)) as Guard<number>,
  boolean: ((value: unknown) => typeof value === "boolean") as Guard<boolean>,
  array:
    <T>(item: Guard<T>): Guard<T[]> =>
    (value: unknown): value is T[] =>
      Array.isArray(value) && value.every(item),
  object:
    <S extends Shape>(shape: S): Guard<ShapeOf<S>> =>
    (value: unknown): value is ShapeOf<S> =>
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value) &&
      Object.entries(shape).every(([key, guard]) => guard((value as Record<string, unknown>)[key])),
};

// ---------------------------------------------------------------------------------------------
// Context: what the protocol layer hands each operation.
// ---------------------------------------------------------------------------------------------

/** Per-session key/value state for the provider (it never sees the protocol's own rows). */
export interface State {
  get<T>(key: string, guard: Guard<T>): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  /**
   * The stored value, or `create()`'s result stored under `key`. Use it for anything that must
   * happen once per session (a document uploaded to the rail, an app push): a poll re-invokes the
   * same operation and must be answered from this state, never by starting the act again.
   */
  once<T>(key: string, guard: Guard<T>, create: () => Promise<T>): Promise<T>;
}

export type HandoffTicket = { url: string; expiresAt: string };

/** Browser hand-offs: a ticketed page URL out, a single-use code back through `callbackUrl`. */
export interface Handoff {
  /** A worker URL (`path?ticket=…`) for the signer's browser. One ticket per request leg: a poll gets the same one. */
  begin(options: { purpose: string; path: `/${string}`; ttlMs: number }): Promise<HandoffTicket>;
  /** Spends a code minted by `page.complete` for this purpose. True exactly once. */
  redeem(code: string, purpose: string): Promise<boolean>;
  /** Whether the page this request leg began has completed (the poll channel's signal). */
  completed(purpose: string): Promise<boolean>;
}

export type Context<R> = { request: R; state: State; handoff: Handoff; now: () => number };

export type AuthorizeContext = Context<AuthorizeRequest> & {
  /** Mints the single-use authorization, bound to this credential and digest set. `data` comes back at `spend`. */
  grant(options: { data: unknown; ttlMs?: number }): Promise<AuthorizeOutcome>;
};

export type SpendResult<T> = { ok: true; data: T } | { ok: false; failure: SignOutcome };

export type SignContext = Context<SignRequest> & {
  /**
   * Spends the authorization named by the request: unknown, spent or expired → `authorization_expired`;
   * another credential → `access_denied`; another digest set → `digest_rejected`. Single use either way.
   */
  spend<T>(guard: Guard<T>): Promise<SpendResult<T>>;
};

export type OpenTicket = {
  id: string;
  purpose: string;
  callbackUrl: string;
  signer: Signer;
  /** The labels of the digests being authorized, for a consent page. Empty on a credential leg. */
  labels: string[];
  expiresAt: string;
};

export interface PageKit {
  /** The open ticket the request carries (query on GET, form field on POST), or a ready 404/410 notice. */
  ticket(request: Request, purpose: string): Promise<OpenTicket | Response>;
  /** Retires the ticket, mints its one code, records the completion and 302s to `callbackUrl?code=…`. */
  complete(ticket: OpenTicket): Promise<Response>;
  /** An HTML page with the worker's safe headers. `body` is trusted HTML: escape every value with `escape`. */
  html(title: string, body: string, status?: number): Response;
  escape(value: string): string;
}

export type PageHandler = (request: Request, page: PageKit) => Promise<Response>;

export interface Provider {
  /** Reported by `GET /v1/health` as `rail`. */
  readonly name: string;
  /** What `sign` answers with. The platform asks `sign` for this format. */
  readonly format: SignatureFormat;
  credential(ctx: Context<CredentialRequest>): Promise<CredentialOutcome>;
  authorize(ctx: AuthorizeContext): Promise<AuthorizeOutcome>;
  sign(ctx: SignContext): Promise<SignOutcome>;
  /** Browser pages, by path. A path must not start with `/v1/`. */
  readonly pages?: Readonly<Record<`/${string}`, PageHandler>>;
}

// ---------------------------------------------------------------------------------------------
// Outcomes. The types are the rules: `sign` can only answer `signed.*` or a non-retryable failure,
// so a provider cannot return `pending` from `sign` or promise that a failed `sign` is retryable.
// ---------------------------------------------------------------------------------------------

export type ErrorCode =
  | "invalid_request"
  | "access_denied"
  | "authorization_expired"
  | "credential_unavailable"
  | "credential_expired"
  | "digest_rejected"
  | "internal_error"
  | `x_${string}`;

export type Failure = { kind: "failed"; error: ErrorCode; description: string; retryable: false };
export type RetryableFailure = {
  kind: "failed";
  error: "temporarily_unavailable" | "internal_error";
  description: string;
  retryable: true;
};
export type Pending = { kind: "pending"; actionUrl?: string; pollAfter?: number; expiresAt: string };
export type CredentialCompleted = {
  kind: "credential";
  format: SignatureFormat;
  id: string;
  certificates?: string[];
  keyAlgoOids?: string[];
  maxSignatureSize?: number;
  expiresAt?: string;
};
export type AuthorizationCompleted = { kind: "authorization"; reference: string; expiresAt: string };
export type Signed = { kind: "signed"; format: SignatureFormat; signatures: Uint8Array[]; certificates?: string[] };

export type CredentialOutcome = CredentialCompleted | Pending | Failure | RetryableFailure;
export type AuthorizeOutcome = AuthorizationCompleted | Pending | Failure | RetryableFailure;
export type SignOutcome = Signed | Failure;

function iso(value: string | Date): string {
  return typeof value === "string" ? value : value.toISOString();
}

function bytes(value: Uint8Array | string): Uint8Array {
  return typeof value === "string" ? Buffer.from(value, "base64") : value;
}

export const credential = {
  raw(input: {
    id: string;
    certificates: string[];
    keyAlgoOids: string[];
    expiresAt?: string | Date;
  }): CredentialCompleted {
    const { expiresAt, ...rest } = input;
    return { kind: "credential", format: "raw", ...rest, ...(expiresAt ? { expiresAt: iso(expiresAt) } : {}) };
  },
  cms(input: {
    id: string;
    maxSignatureSize?: number;
    certificates?: string[];
    keyAlgoOids?: string[];
    expiresAt?: string | Date;
  }): CredentialCompleted {
    const { expiresAt, ...rest } = input;
    return { kind: "credential", format: "cms", ...rest, ...(expiresAt ? { expiresAt: iso(expiresAt) } : {}) };
  },
};

/** At least one channel: a page to send the signer to, a poll interval, or both. */
export function pending(
  input:
    | { actionUrl: string; pollAfter?: number; expiresAt: string | Date }
    | { actionUrl?: string; pollAfter: number; expiresAt: string | Date },
): Pending {
  return {
    kind: "pending",
    ...(input.actionUrl === undefined ? {} : { actionUrl: input.actionUrl }),
    ...(input.pollAfter === undefined ? {} : { pollAfter: input.pollAfter }),
    expiresAt: iso(input.expiresAt),
  };
}

export const signed = {
  /** One raw signature per digest, in order (ECDSA: DER `ECDSA-Sig-Value`; RSA: PKCS#1 v1.5 over DigestInfo). */
  raw(signatures: Array<Uint8Array | string>): Signed {
    return { kind: "signed", format: "raw", signatures: signatures.map(bytes) };
  },
  /** One detached CMS `ContentInfo` per digest, and the chain (PEM, leaf first, no root needed). */
  cms(signatures: Array<Uint8Array | string>, certificates: string[]): Signed {
    return { kind: "signed", format: "cms", signatures: signatures.map(bytes), certificates };
  },
};

/** A final refusal. Use `failed.retryable` only from credential/authorize, and only when nothing was started. */
export function failed(error: ErrorCode, description: string): Failure {
  return { kind: "failed", error, description, retryable: false };
}
failed.retryable = (error: "temporarily_unavailable" | "internal_error", description: string): RetryableFailure => ({
  kind: "failed",
  error,
  description,
  retryable: true,
});
