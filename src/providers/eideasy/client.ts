/**
 * The two eID Easy calls this provider makes, hash-signing flow (container `cades`):
 *
 * - `prepare-files-for-signing` uploads the digest as the file content and names our return URL as
 *   `signature_redirect`; it answers the `doc_id` and the hosted `signing_page_url`.
 * - `download-signed-file` answers the detached CMS (`signed_file_contents`) and, in
 *   `pades_dss_data.certificates`, the certificates around the signer's (the CMS holds the leaf only).
 *
 * Verified against the eID Easy sandbox (test.eideasy.com): the redirect target comes back verbatim,
 * the CMS `messageDigest` equals the digest we uploaded, and the chain lives in `pades_dss_data`.
 */

export type EidEasyClientConfig = { baseUrl: string; clientId: string; secret: string; fetch?: typeof fetch };
export type Prepared = { docId: string; signingPageUrl: string };
export type SignedFile = { cms: Uint8Array; certificates: string[] };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** eID Easy returns base64 DER; PEM is accepted too. */
function toPem(value: string): string {
  if (value.includes("-----BEGIN CERTIFICATE-----")) {
    return value;
  }
  const lines = value.replace(/\s+/g, "").match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

export function createEidEasyClient(config: EidEasyClientConfig) {
  const fetchFn = config.fetch ?? fetch;
  const baseUrl = config.baseUrl.replace(/\/+$/, "");

  async function post(path: string, payload: Record<string, unknown>): Promise<{ status: number; body: unknown }> {
    const response = await fetchFn(`${baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ client_id: config.clientId, secret: config.secret, ...payload }),
      signal: AbortSignal.timeout(20_000),
    });
    return { status: response.status, body: await response.json().catch(() => null) };
  }

  return {
    async prepare(input: { digest: string; fileName: string; returnUrl: string }): Promise<Prepared> {
      const { status, body } = await post("/api/signatures/prepare-files-for-signing", {
        container_type: "cades",
        noemails: true,
        signature_redirect: input.returnUrl,
        files: [{ fileName: input.fileName, mimeType: "application/pdf", fileContent: input.digest }],
      });
      if (!isRecord(body) || typeof body.doc_id !== "string" || typeof body.signing_page_url !== "string") {
        throw new Error(`eID Easy prepare-files-for-signing answered ${status} without doc_id and signing_page_url`);
      }
      return { docId: body.doc_id, signingPageUrl: body.signing_page_url };
    },

    /** `null` when eID Easy holds no signed file for the document (the signer did not sign). */
    async download(docId: string): Promise<SignedFile | null> {
      const { status, body } = await post("/api/signatures/download-signed-file", { doc_id: docId });
      if (status >= 500 || status === 429) {
        throw new Error(`eID Easy download-signed-file answered ${status}`);
      }
      if (!isRecord(body) || typeof body.signed_file_contents !== "string" || body.signed_file_contents === "") {
        return null;
      }
      const dss = isRecord(body.pades_dss_data) ? body.pades_dss_data : {};
      const certificates = Array.isArray(dss.certificates) ? dss.certificates.filter((c) => typeof c === "string") : [];
      return { cms: Buffer.from(body.signed_file_contents, "base64"), certificates: certificates.map(toPem) };
    },
  };
}

export type EidEasyClient = ReturnType<typeof createEidEasyClient>;
