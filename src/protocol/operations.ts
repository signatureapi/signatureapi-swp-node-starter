import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import type {
  AuthorizeContext,
  AuthorizeOutcome,
  CredentialOutcome,
  CredentialRequest,
  Digest,
  Guard,
  Provider,
  SignContext,
  SignOutcome,
  SignRequest,
  State,
} from "../providers/types.ts";
import { failed } from "../providers/types.ts";
import { authenticate } from "./authenticate.ts";
import { grant, spend } from "./authorization.ts";
import type { Operation, Rejection } from "./envelope.ts";
import { isOperation, parseEnvelope } from "./envelope.ts";
import { createHandoff, createPageKit } from "./handoff.ts";
import type { WireOutcome } from "./idempotency.ts";
import { withIdempotency } from "./idempotency.ts";
import type { JwksCache } from "./jwt.ts";
import type { SessionStore, Store } from "./store.ts";

/** The one request-body cap, for operations and pages alike. */
export const MAX_BODY_BYTES = 1024 * 1024;
/** Largest `max_signature_size` the platform accepts (SWP/1 §5.2). */
const MAX_SIGNATURE_SIZE = 53_248;

export type WorkerOptions = {
  provider: Provider;
  store: Store;
  jwks: JwksCache;
  issuer: string;
  /** This worker's public base URL, no trailing slash: the only `aud` it accepts. */
  publicUrl: string;
  connectionTokens: readonly string[];
  now?: () => number;
  log?: (message: string) => void;
};

function wire(status: number, payload: Record<string, unknown>): WireOutcome {
  return { status, body: JSON.stringify(payload) };
}

function toResponse(outcome: WireOutcome): Response {
  return new Response(outcome.body, {
    status: outcome.status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function isHttpUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value);
    return protocol === "https:" || protocol === "http:";
  } catch {
    return false;
  }
}

/**
 * Provider outcome → SWP/1 wire body (§5.1–§5.4). A provider that breaks the contract (a `raw`
 * credential without a chain, a signature count that does not match the digests) is a worker bug:
 * it throws here and is answered like any provider exception.
 */
function toWire(
  provider: Provider,
  outcome: CredentialOutcome | AuthorizeOutcome | SignOutcome,
  digests = 0,
): WireOutcome {
  switch (outcome.kind) {
    case "failed":
      return wire(200, {
        status: "failed",
        error: outcome.error,
        error_description: outcome.description,
        retryable: outcome.retryable,
      });
    case "pending":
      if (outcome.actionUrl !== undefined && !isHttpUrl(outcome.actionUrl)) {
        throw new Error("pending.actionUrl must be an absolute http(s) URL");
      }
      return wire(200, {
        status: "pending",
        ...(outcome.actionUrl === undefined ? {} : { action_url: outcome.actionUrl }),
        ...(outcome.pollAfter === undefined ? {} : { poll_after: outcome.pollAfter }),
        expires_at: outcome.expiresAt,
      });
    case "credential": {
      if (outcome.format !== provider.format) {
        throw new Error(`credential format ${outcome.format} differs from provider format ${provider.format}`);
      }
      if (outcome.format === "raw" && !(outcome.certificates?.length && outcome.keyAlgoOids?.length)) {
        throw new Error("a raw credential needs certificates and keyAlgoOids");
      }
      const size = outcome.maxSignatureSize;
      if (size !== undefined && !(Number.isInteger(size) && size >= 1 && size <= MAX_SIGNATURE_SIZE)) {
        throw new Error(`maxSignatureSize must be an integer in 1..${MAX_SIGNATURE_SIZE}`);
      }
      return wire(200, {
        status: "completed",
        credential: {
          id: outcome.id,
          ...(outcome.format === "cms" ? { signature_format: "cms" } : {}),
          ...(outcome.certificates ? { certificates: outcome.certificates } : {}),
          ...(outcome.keyAlgoOids ? { key_algo_oids: outcome.keyAlgoOids } : {}),
          ...(outcome.format === "cms" && size !== undefined ? { max_signature_size: size } : {}),
          ...(outcome.expiresAt ? { expires_at: outcome.expiresAt } : {}),
        },
      });
    }
    case "authorization":
      return wire(200, {
        status: "completed",
        authorization: { reference: outcome.reference, expires_at: outcome.expiresAt },
      });
    case "signed":
      if (outcome.format !== provider.format || outcome.signatures.length !== digests) {
        throw new Error("sign must answer one signature per digest, in the provider's format");
      }
      if (outcome.format === "cms" && !outcome.certificates?.length) {
        throw new Error("a cms signature needs its certificate chain");
      }
      return wire(200, {
        status: "completed",
        signatures: outcome.signatures.map((signature) => Buffer.from(signature).toString("base64")),
        ...(outcome.format === "cms" ? { certificates: outcome.certificates } : {}),
      });
  }
}

/** Provider state, namespaced away from the protocol's own rows and validated on read. */
const creating = new Map<string, Promise<unknown>>();

function createState(session: SessionStore, sessionId: string): State {
  const get = async <T>(key: string, guard: Guard<T>): Promise<T | undefined> => {
    const value = session.get(`state:${key}`);
    return guard(value) ? value : undefined;
  };
  return {
    get,
    async put(key, value) {
      session.put(`state:${key}`, value);
    },
    async once(key, guard, create) {
      const existing = await get(key, guard);
      if (existing !== undefined) {
        return existing;
      }
      // Two concurrent legs of one session share one `create()` instead of racing two.
      const slot = `${sessionId}\u0000${key}`;
      const running =
        creating.get(slot) ??
        create().then((value) => {
          session.put(`state:${key}`, value);
          return value;
        });
      creating.set(slot, running);
      try {
        return (await running) as Awaited<ReturnType<typeof create>>;
      } finally {
        creating.delete(slot);
      }
    },
  };
}

export function createWorker(options: WorkerOptions): Hono {
  const { provider, store } = options;
  const now = options.now ?? Date.now;
  const log = options.log ?? ((message: string) => console.error(message));
  const app = new Hono();

  app.use(
    bodyLimit({
      maxSize: MAX_BODY_BYTES,
      onError: (c) => c.json({ error: "invalid_request", error_description: "body too large" }, 413),
    }),
  );

  // Shallow liveness (§5.6): never touches the rail or the platform's key set.
  app.get("/v1/health", (c) =>
    c.json({ status: "ok", rail: provider.name, connection_tokens: [...options.connectionTokens] }),
  );

  app.post("/v1/:operation", async (c) => {
    const operation = c.req.param("operation");
    if (!isOperation(operation)) {
      return c.json({ error: "not_found", error_description: `no route for ${c.req.path}` }, 404);
    }
    const rawBody = new Uint8Array(await c.req.arrayBuffer());
    const auth = await authenticate(c.req.raw.headers, rawBody, operation, {
      jwks: options.jwks,
      issuer: options.issuer,
      publicUrl: options.publicUrl,
      connectionTokens: options.connectionTokens,
      store,
      now,
    });
    if ("error" in auth) {
      return c.json({ error: auth.error, error_description: auth.description }, auth.status);
    }
    const idempotencyKey = c.req.header("idempotency-key");
    if (!idempotencyKey) {
      return c.json({ error: "invalid_request", error_description: "missing Idempotency-Key" }, 400);
    }
    const session = store.session(auth.sessionId);
    const outcome = await withIdempotency({
      store: session,
      sessionId: auth.sessionId,
      key: idempotencyKey,
      bodySha256: auth.bodySha256,
      execute: () => execute(operation, auth.body, auth.sessionId, idempotencyKey, session),
    });
    return toResponse(outcome);
  });

  async function execute(
    operation: Operation,
    body: Record<string, unknown>,
    sessionId: string,
    idempotencyKey: string,
    session: SessionStore,
  ): Promise<WireOutcome> {
    const contextFor = (request: CredentialRequest, digests: Digest[] = []) => ({
      state: createState(session, sessionId),
      handoff: createHandoff({
        session,
        sessionId,
        idempotencyKey,
        publicUrl: options.publicUrl,
        signer: request.signer,
        callbackUrl: request.callbackUrl,
        labels: digests.map((digest) => digest.label ?? "(untitled document)"),
        now,
      }),
      now,
    });
    switch (operation) {
      case "credential": {
        const parsed = parseEnvelope(body, "credential");
        if (!parsed.ok) {
          return rejected(parsed.rejection);
        }
        return toWire(provider, await provider.credential({ ...contextFor(parsed.request), request: parsed.request }));
      }
      case "authorize": {
        const parsed = parseEnvelope(body, "authorize");
        if (!parsed.ok) {
          return rejected(parsed.rejection);
        }
        const { request } = parsed;
        const binding = { credentialId: request.credentialId, digests: request.digests.map((digest) => digest.value) };
        const ctx: AuthorizeContext = {
          ...contextFor(request, request.digests),
          request,
          grant: async (grantOptions) => grant(session, binding, grantOptions, now()),
        };
        return toWire(provider, await provider.authorize(ctx));
      }
      case "sign": {
        const parsed = parseEnvelope(body, "sign");
        if (!parsed.ok) {
          return rejected(parsed.rejection);
        }
        return sign(parsed.request, contextFor(parsed.request, parsed.request.digests), session);
      }
    }
  }

  function rejected(rejection: Rejection): WireOutcome {
    return "invalid" in rejection
      ? wire(400, { error: "invalid_request", error_description: rejection.invalid })
      : toWire(provider, rejection.failure);
  }

  /**
   * `sign` is never retryable (§7 honesty clause): once the provider was called, nobody can prove
   * the act did not happen. A provider that throws therefore gets a stored, non-retryable
   * `internal_error`, never a 503 the platform would retry into a second signing act.
   */
  async function sign(
    request: SignRequest,
    base: Omit<SignContext, "request" | "spend">,
    session: SessionStore,
  ): Promise<WireOutcome> {
    if (request.signatureFormat !== provider.format) {
      return toWire(
        provider,
        failed(
          "digest_rejected",
          `signature_format ${request.signatureFormat} is not this worker's ${provider.format}`,
        ),
      );
    }
    const ctx: SignContext = { ...base, request, spend: async (guard) => spend(session, request, guard, now()) };
    try {
      const outcome = await provider.sign(ctx);
      // The types already forbid these; a provider written in plain JavaScript is checked here.
      if (outcome.kind !== "signed" && !(outcome.kind === "failed" && outcome.retryable === false)) {
        throw new Error("sign may only answer signed.* or a non-retryable failure");
      }
      return toWire(provider, outcome, request.digests.length);
    } catch (error) {
      log(`sign failed in provider ${provider.name}: ${error instanceof Error ? error.message : String(error)}`);
      return toWire(provider, failed("internal_error", "the signing provider failed"));
    }
  }

  const pageKit = createPageKit(store, now);
  for (const [path, handler] of Object.entries(provider.pages ?? {})) {
    if (!path.startsWith("/") || path.startsWith("/v1/")) {
      throw new Error(`provider page ${path} must start with / and not with /v1/`);
    }
    app.on(["GET", "POST"], path, (c) => handler(c.req.raw, pageKit));
  }

  app.notFound((c) => c.json({ error: "not_found", error_description: `no route for ${c.req.path}` }, 404));

  // Anything thrown outside `sign` (the platform's key set unreachable, the database, a provider
  // failing in credential/authorize) is an outage: 503, nothing stored, so the platform retries.
  // The caller learns nothing about the cause; the log does.
  app.onError((error, c) => {
    log(`swp worker unavailable: ${error instanceof Error ? error.message : String(error)}`);
    return c.json({ error: "temporarily_unavailable", error_description: "worker is temporarily unavailable" }, 503);
  });

  return app;
}
