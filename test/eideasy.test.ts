import { X509Certificate } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { certificateChain } from "../src/providers/eideasy/chain.ts";
import { createEidEasyClient } from "../src/providers/eideasy/client.ts";
import { createEidEasyProvider } from "../src/providers/eideasy/index.ts";
import { cmsWithLeaf, digestOf, envelope, makeWorker, PUBLIC_URL, type TestWorker, testPki } from "./helpers.ts";

type Pki = Awaited<ReturnType<typeof testPki>>;
const der = (pem: string) => new X509Certificate(pem).raw.toString("base64");

/** A stand-in for eID Easy's two endpoints, recording what the provider sent. */
function fakeEidEasy(pki: Pki) {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  const state = { signed: true };
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const path = new URL(String(input)).pathname;
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    calls.push({ path, body });
    if (path === "/api/signatures/prepare-files-for-signing") {
      return Response.json({ status: "OK", doc_id: "doc_1", signing_page_url: "https://test.eideasy.test/sign/doc_1" });
    }
    if (!state.signed) {
      return Response.json({ status: "error", message: "File not signed" }, { status: 400 });
    }
    return Response.json({
      status: "OK",
      signed_file_contents: Buffer.from(cmsWithLeaf(pki.leaf.certificate)).toString("base64"),
      pades_dss_data: { certificates: [pki.ocsp.pem, pki.root.pem, pki.leaf.pem, pki.intermediate.pem].map(der) },
    });
  }) as typeof fetch;
  return {
    calls,
    state,
    client: createEidEasyClient({ baseUrl: "https://test.eideasy.test", clientId: "id", secret: "s", fetch: fetchFn }),
  };
}

describe("eideasy provider", () => {
  let pki: Pki;
  let worker: TestWorker;
  let eid: ReturnType<typeof fakeEidEasy>;

  beforeAll(async () => {
    pki = await testPki();
    eid = fakeEidEasy(pki);
    worker = makeWorker(createEidEasyProvider(eid.client));
  });

  const authorizeBody = (session: string) =>
    envelope(session, { credential_id: "eideasy", digests: [digestOf("pdf byte range", "Contract.pdf")] });

  it("declares a cms credential without certificates", async () => {
    const body = await (await worker.call("credential", envelope("sgs_e0"))).json();
    expect(body).toEqual({
      status: "completed",
      credential: { id: "eideasy", signature_format: "cms", max_signature_size: 16_384 },
    });
  });

  it("uploads the digest once, returns through the worker page, and signs with the downloaded CMS", async () => {
    const started = (await (await worker.call("authorize", authorizeBody("sgs_e1"))).json()) as Record<string, unknown>;
    expect(started).toMatchObject({
      status: "pending",
      action_url: "https://test.eideasy.test/sign/doc_1",
      poll_after: 3,
    });
    await worker.call("authorize", authorizeBody("sgs_e1"));
    const prepares = eid.calls.filter((call) => call.path.endsWith("prepare-files-for-signing"));
    expect(prepares).toHaveLength(1);
    const prepared = prepares[0]?.body ?? {};
    expect(prepared).toMatchObject({ container_type: "cades", noemails: true });
    expect((prepared.files as Array<{ fileContent: string }>)[0]?.fileContent).toBe(digestOf("pdf byte range").value);

    // eID Easy sends the browser back to `signature_redirect` verbatim.
    const back = await worker.app.request(String(prepared.signature_redirect));
    expect(back.status).toBe(302);
    const code = new URL(back.headers.get("location") ?? "").searchParams.get("code");
    expect(String(prepared.signature_redirect).startsWith(`${PUBLIC_URL}/eideasy/return?ticket=`)).toBe(true);

    const resumed = await worker.call(
      "authorize",
      { ...authorizeBody("sgs_e1"), callback: { code } },
      {
        idempotencyKey: "sgs_e1/authorize/1/resume",
      },
    );
    const { authorization } = (await resumed.json()) as { authorization: { reference: string } };
    const signBody = envelope("sgs_e1", {
      credential_id: "eideasy",
      digests: [digestOf("pdf byte range")],
      authorization: { reference: authorization.reference },
      signature_format: "cms",
    });
    const signedBody = (await (await worker.call("sign", signBody)).json()) as Record<string, unknown>;
    expect(signedBody.status).toBe("completed");
    expect(signedBody.certificates).toEqual(
      [pki.leaf.pem, pki.intermediate.pem].map((pem) => new X509Certificate(pem).toString()),
    );
    expect(signedBody.signatures).toEqual([Buffer.from(cmsWithLeaf(pki.leaf.certificate)).toString("base64")]);
  });

  it("refuses with access_denied when the signer did not sign", async () => {
    const started = (await (await worker.call("authorize", authorizeBody("sgs_e2"))).json()) as Record<string, unknown>;
    expect(started.status).toBe("pending");
    const redirect = eid.calls.filter((call) => call.path.endsWith("prepare-files-for-signing")).at(-1)?.body;
    await worker.app.request(String(redirect?.signature_redirect));
    const polled = (await (await worker.call("authorize", authorizeBody("sgs_e2"))).json()) as {
      authorization: { reference: string };
    };
    eid.state.signed = false;
    const signBody = envelope("sgs_e2", {
      credential_id: "eideasy",
      digests: [digestOf("pdf byte range")],
      authorization: { reference: polled.authorization.reference },
      signature_format: "cms",
    });
    expect(await (await worker.call("sign", signBody)).json()).toMatchObject({
      error: "access_denied",
      retryable: false,
    });
    eid.state.signed = true;
  });

  it("signs exactly one SHA-256 digest per request", async () => {
    const body = envelope("sgs_e3", { credential_id: "eideasy", digests: [digestOf("a"), digestOf("b")] });
    expect(await (await worker.call("authorize", body)).json()).toMatchObject({ error: "digest_rejected" });
  });

  it("builds the chain from the pool: leaf first, no root, no OCSP responder", () => {
    const pool = [pki.ocsp.pem, pki.root.pem, pki.intermediate.pem];
    const chain = certificateChain(cmsWithLeaf(pki.leaf.certificate), pool).map((pem) => new X509Certificate(pem));
    expect(chain.map((certificate) => certificate.subject)).toEqual(["CN=Ada Lovelace", "CN=Test Intermediate"]);
  });
});
