import { verify, X509Certificate } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { createByoProvider } from "../src/providers/byo/index.ts";
import { digestOf, envelope, makeWorker, PUBLIC_URL, submitConsent, type TestWorker, testPki } from "./helpers.ts";

const EC_SHA256 = "1.2.840.10045.4.3.2";

describe("byo provider", () => {
  let worker: TestWorker;
  let chain: string[];

  beforeAll(async () => {
    const { root, intermediate, leaf } = await testPki();
    chain = [leaf.pem, intermediate.pem, root.pem];
    worker = makeWorker(createByoProvider({ certificates: chain, privateKeyPem: leaf.privateKeyPem }));
  });

  const authorizeBody = (session: string, message = "contract") =>
    envelope(session, { credential_id: "byo", digests: [digestOf(message)] });

  async function sign(session: string, reference: string, message = "contract") {
    const body = envelope(session, {
      credential_id: "byo",
      digests: [digestOf(message)],
      authorization: { reference },
      sign_algo_oid: EC_SHA256,
    });
    return (await (await worker.call("sign", body)).json()) as Record<string, unknown>;
  }

  it("answers credential with the static chain and ecdsa-with-SHA256", async () => {
    const body = (await (await worker.call("credential", envelope("sgs_b1"))).json()) as {
      credential: Record<string, unknown>;
    };
    expect(body.credential).toMatchObject({ id: "byo", certificates: chain, key_algo_oids: [EC_SHA256] });
  });

  it("signs after the redirect channel: consent POST, then resume with the code", async () => {
    const started = (await (await worker.call("authorize", authorizeBody("sgs_b2"))).json()) as Record<string, string>;
    expect(started).toMatchObject({ status: "pending", poll_after: 2 });
    expect(started.action_url?.startsWith(`${PUBLIC_URL}/consent?ticket=sgs_b2.`)).toBe(true);
    const consent = await submitConsent(worker.app, started.action_url ?? "");
    expect(consent.status).toBe(302);
    const resumed = await worker.call(
      "authorize",
      { ...authorizeBody("sgs_b2"), callback: { code: consent.code } },
      {
        idempotencyKey: "sgs_b2/authorize/1/resume",
      },
    );
    const { authorization } = (await resumed.json()) as { authorization: { reference: string } };
    const signedBody = await sign("sgs_b2", authorization.reference);
    const [signature] = signedBody.signatures as string[];
    // ECDSA over the raw digest equals ecdsa-with-SHA256 over the message the digest was taken of.
    const leaf = new X509Certificate(chain[0] ?? "");
    expect(verify("sha256", Buffer.from("contract"), leaf.publicKey, Buffer.from(signature ?? "", "base64"))).toBe(
      true,
    );
  });

  it("completes on the poll channel once the page was submitted", async () => {
    const started = (await (await worker.call("authorize", authorizeBody("sgs_b3"))).json()) as Record<string, string>;
    const again = (await (await worker.call("authorize", authorizeBody("sgs_b3"))).json()) as Record<string, string>;
    expect(again.action_url).toBe(started.action_url);
    await submitConsent(worker.app, started.action_url ?? "");
    const polled = await (await worker.call("authorize", authorizeBody("sgs_b3"))).json();
    expect(polled).toMatchObject({ status: "completed", authorization: { reference: expect.any(String) } });
  });

  it("mints one code per ticket and refuses a spent code", async () => {
    const started = (await (await worker.call("authorize", authorizeBody("sgs_b4"))).json()) as Record<string, string>;
    const { code } = await submitConsent(worker.app, started.action_url ?? "");
    expect((await submitConsent(worker.app, started.action_url ?? "")).status).toBe(404);
    const resume = { ...authorizeBody("sgs_b4"), callback: { code } };
    await worker.call("authorize", resume, { idempotencyKey: "sgs_b4/authorize/1/resume" });
    const replay = await worker.call("authorize", resume, { idempotencyKey: "sgs_b4/authorize/2/resume" });
    expect(await replay.json()).toMatchObject({ status: "failed", error: "access_denied" });
  });

  it("shows an expired consent link as 410", async () => {
    const started = (await (await worker.call("authorize", authorizeBody("sgs_b5"))).json()) as Record<string, string>;
    worker.clock.now += 6 * 60 * 1000;
    expect((await worker.app.request(started.action_url ?? "")).status).toBe(410);
    worker.clock.now -= 6 * 60 * 1000;
  });

  it("refuses an unknown credential", async () => {
    const body = envelope("sgs_b6", { credential_id: "other", digests: [digestOf("x")] });
    expect(await (await worker.call("authorize", body)).json()).toMatchObject({ error: "credential_unavailable" });
  });
});
