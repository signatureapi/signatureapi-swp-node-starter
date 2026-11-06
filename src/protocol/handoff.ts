import { randomBytes } from "node:crypto";
import type { Handoff, HandoffTicket, OpenTicket, PageKit, Signer } from "../providers/types.ts";
import { is } from "../providers/types.ts";
import type { SessionStore, Store } from "./store.ts";

/**
 * Browser hand-offs (SWP/1 §4, §5.1). An interactive leg answers `pending` with an `action_url`
 * on this worker that carries an unguessable ticket. The page the signer lands on (a consent form,
 * or the return URL of a provider's hosted page) completes the ticket: the ticket is retired, one
 * code is minted, and the browser is 302'd to the platform's `callback_url?code=…`. The platform
 * then resumes the operation with `callback.code`, which the provider redeems exactly once.
 *
 * One ticket mints one code: `complete` takes the ticket in the same step it mints the code, so a
 * double click or the back button finds no ticket and no second code exists.
 */

/** `leg` is the Idempotency-Key of the request that began it: completion counts for that leg only. */
type Ticket = {
  purpose: string;
  leg: string;
  callbackUrl: string;
  signer: Signer;
  labels: string[];
  expiresAt: number;
};
type Code = { purpose: string };

const isSigner = is.object({ id: is.string, name: is.string, email: is.string });
const isTicket = is.object({
  purpose: is.string,
  leg: is.string,
  callbackUrl: is.string,
  signer: isSigner,
  labels: is.array(is.string),
  expiresAt: is.number,
});
const isCode = is.object({ purpose: is.string });
const isLegTicket = is.object({ url: is.string, expiresAt: is.string });

/** A ticket row outlives its window so an expired link answers 410 "expired", not 404 "unknown". */
const TICKET_GRACE_MS = 60 * 60 * 1000;
/** How long the platform has to resume with a minted code. */
const CODE_TTL_MS = 15 * 60 * 1000;
const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;

export function createHandoff(input: {
  session: SessionStore;
  sessionId: string;
  idempotencyKey: string;
  publicUrl: string;
  signer: Signer;
  callbackUrl: string;
  labels: string[];
  now: () => number;
}): Handoff {
  const { session } = input;
  return {
    async begin({ purpose, path, ttlMs }): Promise<HandoffTicket> {
      // Re-invocation (a poll tick) answers from current state: the same leg gets the same ticket,
      // with the expiry it was minted with, even if that window has since run out.
      const legKey = `leg:${input.idempotencyKey}:${purpose}`;
      const existing = session.get(legKey);
      if (isLegTicket(existing)) {
        return existing;
      }
      const id = `${input.sessionId}.${randomBytes(24).toString("base64url")}`;
      const expiresAt = input.now() + ttlMs;
      const ticket: Ticket = {
        purpose,
        leg: input.idempotencyKey,
        callbackUrl: input.callbackUrl,
        signer: input.signer,
        labels: input.labels,
        expiresAt,
      };
      session.put(`ticket:${id}`, ticket, ttlMs + TICKET_GRACE_MS);
      const leg: HandoffTicket = {
        url: `${input.publicUrl}${path}?ticket=${encodeURIComponent(id)}`,
        expiresAt: new Date(expiresAt).toISOString(),
      };
      session.put(legKey, leg, ttlMs + TICKET_GRACE_MS);
      return leg;
    },
    async redeem(code, purpose) {
      const stored = session.take(`code:${code}`);
      return isCode(stored) && stored.purpose === purpose;
    },
    async completed(purpose) {
      return session.get(`completed:${input.idempotencyKey}:${purpose}`) === true;
    },
  };
}

/**
 * Headers for every browser-facing page. No `frame-ancestors`: ceremonies can be embedded in an
 * iframe and the signer's redirect runs inside it. No `form-action`: browsers enforce it across the
 * redirect chain that follows a form POST, and the POST answers a 302 to the platform's origin.
 */
export const PAGE_HEADERS: Readonly<Record<string, string>> = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

const ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ESCAPES[c] ?? c);
}

export function htmlPage(title: string, body: string, status = 200): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;color:#111}button{margin-top:1rem;padding:.6rem 1.2rem;font:inherit}</style></head><body>${body}</body></html>`;
  return new Response(html, { status, headers: PAGE_HEADERS });
}

function notice(title: string, text: string, status: number): Response {
  return htmlPage(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(text)}</p>`, status);
}

function withCode(callbackUrl: string, code: string): string {
  return `${callbackUrl}${callbackUrl.includes("?") ? "&" : "?"}code=${encodeURIComponent(code)}`;
}

export function createPageKit(store: Store, now: () => number): PageKit {
  const unknown = () =>
    notice("This link is no longer valid", "It was already used or never existed. Return to the signing page.", 404);
  return {
    async ticket(request, purpose) {
      const id =
        request.method === "POST"
          ? String((await request.formData()).get("ticket") ?? "")
          : (new URL(request.url).searchParams.get("ticket") ?? "");
      const sessionId = id.slice(0, Math.max(id.indexOf("."), 0));
      if (!SESSION_ID.test(sessionId)) {
        return unknown();
      }
      const stored = store.session(sessionId).get(`ticket:${id}`);
      if (!isTicket(stored) || stored.purpose !== purpose) {
        return unknown();
      }
      if (stored.expiresAt <= now()) {
        return notice("This link has expired", "Return to the signing page and start the step again.", 410);
      }
      const { expiresAt, purpose: _purpose, leg: _leg, ...rest } = stored;
      return { id, purpose, ...rest, expiresAt: new Date(expiresAt).toISOString() };
    },
    async complete(ticket: OpenTicket) {
      const sessionId = ticket.id.slice(0, ticket.id.indexOf("."));
      const session = store.session(sessionId);
      // Taken, not read: whoever takes the ticket mints the only code it will ever have.
      const taken = session.take(`ticket:${ticket.id}`);
      if (!isTicket(taken)) {
        return unknown();
      }
      const code = randomBytes(24).toString("base64url");
      session.put(`code:${code}`, { purpose: taken.purpose } satisfies Code, CODE_TTL_MS);
      session.put(`completed:${taken.leg}:${taken.purpose}`, true);
      return new Response(null, {
        status: 302,
        headers: { location: withCode(ticket.callbackUrl, code), "cache-control": "no-store" },
      });
    },
    html: htmlPage,
    escape: escapeHtml,
  };
}
