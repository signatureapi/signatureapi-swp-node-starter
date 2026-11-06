import type { Provider } from "../types.ts";
import { credential, failed, is, OID, pending, signed } from "../types.ts";
import { certificateChain } from "./chain.ts";
import { createEidEasyClient, type EidEasyClient } from "./client.ts";

/**
 * eID Easy (https://eideasy.com): an aggregator of qualified signing methods (Smart-ID, Mobile-ID,
 * national eID cards and more). The signer picks a method on eID Easy's hosted page, and eID Easy
 * builds the CMS itself, so this is a `cms` provider with no certificate at `credential`: the signer
 * certificate is only known once they signed, and arrives with the `sign` response.
 *
 * Flow: `authorize` uploads the digest and answers `pending` with eID Easy's signing page; eID Easy
 * sends the browser back to our return page, which hands the platform a code; the resumed
 * `authorize` grants; `sign` downloads the signed CMS.
 */

const CREDENTIAL_ID = "eideasy";
const PURPOSE = "eideasy-return";
const RETURN_PATH = "/eideasy/return";
const SIGNING_WINDOW_MS = 10 * 60 * 1000;

const isDocument = is.object({ docId: is.string, signingPageUrl: is.string, expiresAt: is.string });

export function createEidEasyProvider(client: EidEasyClient): Provider {
  return {
    name: "eideasy",
    format: "cms",

    async credential() {
      return credential.cms({ id: CREDENTIAL_ID, maxSignatureSize: 16_384 });
    },

    async authorize(ctx) {
      const { credentialId, digests, callbackCode } = ctx.request;
      const [digest] = digests;
      if (credentialId !== CREDENTIAL_ID) {
        return failed("credential_unavailable", "unknown credential");
      }
      if (digest === undefined || digests.length !== 1 || digest.hashAlgorithmOid !== OID.sha256) {
        return failed("digest_rejected", "eID Easy signs exactly one SHA-256 digest per request");
      }
      if (callbackCode !== undefined || (await ctx.handoff.completed(PURPOSE))) {
        const document = await ctx.state.get("document", isDocument);
        const redeemed = callbackCode === undefined || (await ctx.handoff.redeem(callbackCode, PURPOSE));
        return document && redeemed
          ? ctx.grant({ data: { docId: document.docId } })
          : failed("access_denied", "unknown or already used signing link");
      }
      // Once per session: a poll re-enters here and must not upload the digest a second time.
      const document = await ctx.state.once("document", isDocument, async () => {
        const ticket = await ctx.handoff.begin({ purpose: PURPOSE, path: RETURN_PATH, ttlMs: SIGNING_WINDOW_MS });
        const prepared = await client.prepare({
          digest: digest.value,
          fileName: digest.label ?? "document.pdf",
          returnUrl: ticket.url,
        });
        return { ...prepared, expiresAt: ticket.expiresAt };
      });
      return pending({ actionUrl: document.signingPageUrl, pollAfter: 3, expiresAt: document.expiresAt });
    },

    async sign(ctx) {
      const authorization = await ctx.spend(is.object({ docId: is.string }));
      if (!authorization.ok) {
        return authorization.failure;
      }
      const file = await client.download(authorization.data.docId);
      if (!file) {
        return failed("access_denied", "the signer did not sign in eID Easy");
      }
      return signed.cms([file.cms], certificateChain(file.cms, file.certificates));
    },

    pages: {
      // eID Easy sends the signer's browser here (a GET) once the hosted page is done.
      [RETURN_PATH]: async (request, page) => {
        const ticket = await page.ticket(request, PURPOSE);
        return ticket instanceof Response ? ticket : page.complete(ticket);
      },
    },
  };
}

/** `EIDEASY_CLIENT_ID`, `EIDEASY_SECRET`, and `EIDEASY_BASE_URL` (the sandbox by default). */
export function eidEasyFromEnv(env: NodeJS.ProcessEnv): Provider {
  const clientId = env.EIDEASY_CLIENT_ID?.trim();
  const secret = env.EIDEASY_SECRET?.trim();
  if (!clientId || !secret) {
    throw new Error("eideasy: EIDEASY_CLIENT_ID and EIDEASY_SECRET are required");
  }
  const baseUrl = env.EIDEASY_BASE_URL?.trim() || "https://test.eideasy.com";
  return createEidEasyProvider(createEidEasyClient({ baseUrl, clientId, secret }));
}
