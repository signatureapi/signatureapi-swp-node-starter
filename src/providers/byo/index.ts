import { createPrivateKey, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/p256";
import type { Provider } from "../types.ts";
import { credential, failed, is, OID, pending, signed } from "../types.ts";

/**
 * Bring your own: a static P-256 key and its certificate chain, plus a consent page. It is the
 * smallest complete provider (one interactive leg, `raw` signatures) and the one the conformance
 * tester runs against. Use it as the template for a rail that signs a digest with a key it holds
 * or reaches (an HSM, a cloud KMS, a QTSP's signHash).
 *
 * It is not a qualified signature: a key in an environment variable is not a QSCD.
 */

const CREDENTIAL_ID = "byo";
const PURPOSE = "consent";
const CONSENT_PATH = "/consent";
const CONSENT_WINDOW_MS = 5 * 60 * 1000;

export type ByoConfig = { certificates: string[]; privateKeyPem: string };

export function createByoProvider(config: ByoConfig): Provider {
  const [leafPem] = config.certificates;
  if (leafPem === undefined) {
    throw new Error("byo: the certificate chain is empty");
  }
  const leaf = new X509Certificate(leafPem);
  const key = createPrivateKey(config.privateKeyPem);
  const jwk = key.export({ format: "jwk" });
  const leafJwk = leaf.publicKey.export({ format: "jwk" });
  if (jwk.crv !== "P-256" || !jwk.d) {
    throw new Error("byo: the private key must be a P-256 (prime256v1) key");
  }
  if (jwk.x !== leafJwk.x || jwk.y !== leafJwk.y) {
    throw new Error("byo: the private key does not match the leaf certificate");
  }
  const privateKey = Buffer.from(jwk.d, "base64url");

  return {
    name: "byo",
    format: "raw",

    async credential() {
      return credential.raw({
        id: CREDENTIAL_ID,
        certificates: config.certificates,
        keyAlgoOids: [OID.ecdsaWithSha256],
        expiresAt: new Date(leaf.validTo),
      });
    },

    async authorize(ctx) {
      const { credentialId, digests, callbackCode } = ctx.request;
      if (credentialId !== CREDENTIAL_ID) {
        return failed("credential_unavailable", "unknown credential");
      }
      if (digests.some((digest) => digest.hashAlgorithmOid !== OID.sha256)) {
        return failed("digest_rejected", "this worker signs SHA-256 digests only");
      }
      // Redirect channel: the platform resumes with the code. Poll channel: the page completed.
      if (callbackCode !== undefined) {
        return (await ctx.handoff.redeem(callbackCode, PURPOSE))
          ? ctx.grant({ data: {} })
          : failed("access_denied", "unknown or already used consent link");
      }
      if (await ctx.handoff.completed(PURPOSE)) {
        return ctx.grant({ data: {} });
      }
      const ticket = await ctx.handoff.begin({ purpose: PURPOSE, path: CONSENT_PATH, ttlMs: CONSENT_WINDOW_MS });
      return pending({ actionUrl: ticket.url, pollAfter: 2, expiresAt: ticket.expiresAt });
    },

    async sign(ctx) {
      const authorization = await ctx.spend(is.object({}));
      if (!authorization.ok) {
        return authorization.failure;
      }
      if (ctx.request.signAlgoOid !== OID.ecdsaWithSha256) {
        return failed("digest_rejected", `sign_algo_oid must be ${OID.ecdsaWithSha256}`);
      }
      // ECDSA signs the raw digest (noble 1.9 never prehashes), low-S, DER-encoded (§5.4).
      return signed.raw(
        ctx.request.digests.map((digest) => p256.sign(digest.bytes, privateKey, { lowS: true }).toDERRawBytes()),
      );
    },

    pages: {
      // A GET only shows the form: link scanners follow GETs, so the side effect sits behind the POST.
      [CONSENT_PATH]: async (request, page) => {
        const ticket = await page.ticket(request, PURPOSE);
        if (ticket instanceof Response) {
          return ticket;
        }
        if (request.method === "POST") {
          return page.complete(ticket);
        }
        const items = ticket.labels.map((label) => `<li>${page.escape(label)}</li>`).join("");
        return page.html(
          "Authorize your signature",
          `<h1>Authorize your signature</h1><p>${page.escape(ticket.signer.name)}, you are about to sign:</p><ul>${items}</ul>` +
            `<form method="post" action="${CONSENT_PATH}"><input type="hidden" name="ticket" value="${page.escape(ticket.id)}">` +
            `<button type="submit">Authorize</button></form>`,
        );
      },
    },
  };
}

/** `BYO_CERTIFICATES_PEM` (chain, leaf first) and `BYO_PRIVATE_KEY_PEM`, or their `_FILE` variants. */
export function byoFromEnv(env: NodeJS.ProcessEnv): Provider {
  const read = (name: string): string => {
    const file = env[`${name}_FILE`];
    const value = file ? readFileSync(file, "utf8") : env[name]?.replace(/\\n/g, "\n");
    if (!value?.trim()) {
      throw new Error(`byo: ${name} or ${name}_FILE is required`);
    }
    return value;
  };
  const certificates = read("BYO_CERTIFICATES_PEM").match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
  );
  return createByoProvider({ certificates: certificates ?? [], privateKeyPem: read("BYO_PRIVATE_KEY_PEM") });
}
