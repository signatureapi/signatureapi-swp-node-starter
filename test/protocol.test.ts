import { beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.ts";
import { JwksCache } from "../src/protocol/jwt.ts";
import { createWorker } from "../src/protocol/operations.ts";
import { openStore } from "../src/protocol/store.ts";
import { createByoProvider } from "../src/providers/byo/index.ts";
import type { Provider } from "../src/providers/types.ts";
import { credential, failed, pending, signed } from "../src/providers/types.ts";
import {
  CONNECTION_TOKEN,
  digestOf,
  envelope,
  makeWorker,
  PUBLIC_URL,
  sha256,
  type TestWorker,
  testPki,
} from "./helpers.ts";

/** A provider whose every leg completes headlessly, so the protocol layer is tested on its own. */
function headless(overrides: Partial<Provider> = {}): Provider {
  return {
    name: "headless",
    format: "raw",
    credential: async () => credential.raw({ id: "c1", certificates: ["PEM"], keyAlgoOids: ["1.2.840.10045.4.3.2"] }),
    authorize: async (ctx) => ctx.grant({ data: { n: 1 } }),
    sign: async (ctx) => {
      const spent = await ctx.spend((value): value is { n: number } => typeof value === "object" && value !== null);
      return spent.ok ? signed.raw(ctx.request.digests.map(() => new Uint8Array([1, 2, 3]))) : spent.failure;
    },
    ...overrides,
  };
}

const signBody = (session: string, reference: string) =>
  envelope(session, {
    credential_id: "c1",
    digests: [digestOf("doc")],
    authorization: { reference },
    sign_algo_oid: "1.2.840.10045.4.3.2",
  });

async function authorizeHeadless(worker: TestWorker, session: string): Promise<string> {
  const response = await worker.call(
    "authorize",
    envelope(session, { credential_id: "c1", digests: [digestOf("doc")] }),
  );
  return ((await response.json()) as { authorization: { reference: string } }).authorization.reference;
}

describe("request authentication (§6)", () => {
  let worker: TestWorker;
  beforeAll(() => {
    worker = makeWorker(headless());
  });

  it("answers health with the rail and the connection tokens, unauthenticated", async () => {
    const response = await worker.app.request("/v1/health");
    expect(await response.json()).toEqual({ status: "ok", rail: "headless", connection_tokens: [CONNECTION_TOKEN] });
  });

  it.each([
    ["wrong aud", { claims: { aud: "https://other.example" } }, 401, "unexpected aud"],
    ["wrong iss", { claims: { iss: "https://evil.example" } }, 401, "unexpected iss"],
    ["expired token", { claims: { iat: 1_000, exp: 1_300 } }, 401, "token expired"],
    ["unlisted connection token", { claims: { connection_token: "swpct_other" } }, 401, "connection token not allowed"],
    ["tampered body", { sentBody: JSON.stringify(envelope("sgs_t", { scheme: "x" })) }, 401, "body_sha256 mismatch"],
    ["wrong Content-Digest", { headers: { "content-digest": "sha-256=:AAAA:" } }, 400, "Content-Digest mismatch"],
    ["missing protocol header", { headers: { "signatureapi-protocol": null } }, 400, "missing SignatureAPI-Protocol"],
    ["missing Idempotency-Key", { idempotencyKey: null }, 400, "missing Idempotency-Key"],
  ] as const)("refuses a %s", async (_name, options, status, description) => {
    const response = await worker.call("credential", envelope("sgs_t"), options);
    expect(response.status).toBe(status);
    expect(((await response.json()) as { error_description: string }).error_description).toBe(description);
  });

  it("refuses a replayed jti, and a refused request does not spend its jti", async () => {
    const claims = { jti: "fixed-jti" };
    const headers = { "content-digest": "sha-256=:AAAA:" };
    expect((await worker.call("credential", envelope("sgs_jti"), { claims, headers })).status).toBe(400);
    expect((await worker.call("credential", envelope("sgs_jti"), { claims })).status).toBe(200);
    const replay = await worker.call("credential", envelope("sgs_jti"), { claims });
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ error_description: "replayed jti" });
  });

  it("refuses a token minted for another session", async () => {
    const body = envelope("sgs_t");
    const swp = { session: "sgs_other", operation: "credential", body_sha256: sha256(JSON.stringify(body)) };
    const response = await worker.call("credential", body, { claims: { swp } });
    expect(await response.json()).toMatchObject({ error: "invalid_token", error_description: "session mismatch" });
  });

  it("caps the body at 1 MiB", async () => {
    const response = await worker.call("credential", { ...envelope("sgs_big"), pad: "x".repeat(1024 * 1024) });
    expect(response.status).toBe(413);
  });
});

describe("idempotency (§7)", () => {
  it("replays a completed sign byte for byte without signing twice", async () => {
    let signatures = 0;
    const worker = makeWorker(
      headless({
        sign: async (ctx) => {
          signatures += 1;
          const spent = await ctx.spend((v): v is unknown => v !== undefined);
          return spent.ok ? signed.raw([new Uint8Array([signatures])]) : spent.failure;
        },
      }),
    );
    const reference = await authorizeHeadless(worker, "sgs_i1");
    const first = await (await worker.call("sign", signBody("sgs_i1", reference))).text();
    const second = await (await worker.call("sign", signBody("sgs_i1", reference))).text();
    expect(second).toBe(first);
    expect(signatures).toBe(1);
  });

  it("answers 409 for the same key with another body", async () => {
    const worker = makeWorker(headless());
    await worker.call("credential", envelope("sgs_i2"));
    const response = await worker.call("credential", envelope("sgs_i2", { scheme: "other" }));
    expect(response.status).toBe(409);
  });

  it("answers 409 while the same key is executing", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const credential = async () => {
      await gate;
      return failed("access_denied", "no");
    };
    const worker = makeWorker(headless({ credential }));
    const first = worker.call("credential", envelope("sgs_i3"));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect((await worker.call("credential", envelope("sgs_i3"))).status).toBe(409);
    release();
    expect((await first).status).toBe(200);
  });

  it("never stores pending, so a poll re-executes", async () => {
    let calls = 0;
    const worker = makeWorker(
      headless({
        authorize: async (ctx) => {
          calls += 1;
          return calls < 2
            ? pending({ pollAfter: 1, expiresAt: new Date(ctx.now() + 60_000) })
            : ctx.grant({ data: 1 });
        },
      }),
    );
    const body = envelope("sgs_i4", { credential_id: "c1", digests: [digestOf("doc")] });
    expect(await (await worker.call("authorize", body)).json()).toMatchObject({ status: "pending", poll_after: 1 });
    expect(await (await worker.call("authorize", body)).json()).toMatchObject({ status: "completed" });
  });

  it("turns a provider that throws in sign into a stored, non-retryable internal_error", async () => {
    let calls = 0;
    const worker = makeWorker(
      headless({
        sign: async () => {
          calls += 1;
          throw new Error("rail exploded");
        },
      }),
    );
    const reference = await authorizeHeadless(worker, "sgs_i5");
    const first = await worker.call("sign", signBody("sgs_i5", reference));
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({
      status: "failed",
      error: "internal_error",
      error_description: "the signing provider failed",
      retryable: false,
    });
    await worker.call("sign", signBody("sgs_i5", reference));
    expect(calls).toBe(1);
    expect(worker.logs.join()).toContain("rail exploded");
  });
});

describe("authorization and envelope", () => {
  it("spends an authorization once and binds it to the digest set", async () => {
    const worker = makeWorker(headless());
    const reference = await authorizeHeadless(worker, "sgs_a1");
    const other = envelope("sgs_a1", {
      credential_id: "c1",
      digests: [digestOf("another document")],
      authorization: { reference },
      sign_algo_oid: "1.2.840.10045.4.3.2",
    });
    expect(await (await worker.call("sign", other)).json()).toMatchObject({ error: "digest_rejected" });
    const retry = await worker.call("sign", signBody("sgs_a1", reference), { idempotencyKey: "sgs_a1/sign/2" });
    expect(await retry.json()).toMatchObject({ error: "authorization_expired" });
  });

  it("rejects a digest whose length does not match its algorithm with 400", async () => {
    const worker = makeWorker(headless());
    const body = envelope("sgs_e1", {
      credential_id: "c1",
      digests: [{ value: "AAAA", hash_algorithm_oid: "2.16.840.1.101.3.4.2.1", label: "x" }],
    });
    expect((await worker.call("authorize", body)).status).toBe(400);
  });
});

describe("startup", () => {
  it("refuses to start without SIGNATUREAPI_CONNECTION_TOKENS", () => {
    const env = { PUBLIC_URL, PROVIDER: "byo", SIGNATUREAPI_CONNECTION_TOKENS: " , " };
    expect(() => loadConfig(env)).toThrow("SIGNATUREAPI_CONNECTION_TOKENS");
    expect(loadConfig({ ...env, SIGNATUREAPI_CONNECTION_TOKENS: "swpct_a, swpct_b" }).connectionTokens).toEqual([
      "swpct_a",
      "swpct_b",
    ]);
  });

  it("refuses provider pages under /v1/ and a key that does not match the leaf", async () => {
    const options = {
      store: openStore(":memory:"),
      jwks: new JwksCache("http://unused"),
      issuer: "i",
      publicUrl: PUBLIC_URL,
      connectionTokens: ["t"],
    };
    const provider = headless({ pages: { "/v1/consent": async () => new Response() } });
    expect(() => createWorker({ ...options, provider })).toThrow("/v1/");
    const { leaf, intermediate } = await testPki();
    expect(() => createByoProvider({ certificates: [leaf.pem], privateKeyPem: intermediate.privateKeyPem })).toThrow(
      "does not match",
    );
  });
});
