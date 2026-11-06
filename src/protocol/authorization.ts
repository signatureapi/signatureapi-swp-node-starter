import { randomBytes } from "node:crypto";
import type { AuthorizationCompleted, Guard, SignRequest, SpendResult } from "../providers/types.ts";
import { failed, is } from "../providers/types.ts";
import type { SessionStore } from "./store.ts";

/**
 * The authorization a provider grants at `authorize` and spends at `sign` (the SAD, in CSC terms;
 * SWP/1 §5.3, §5.4). It binds one credential and the exact digest set, it is single use whatever
 * the outcome of the `sign` that spends it, and it is short-lived. The provider's own `data` (a
 * rail document id, a rail SAD) travels with it and comes back validated by the provider's guard.
 */

type Sad = { credentialId: string; digests: string[]; expiresAt: number; data: unknown };

const isSad = is.object({ credentialId: is.string, digests: is.array(is.string), expiresAt: is.number });

/** Industry norm for a SAD: about five minutes, not extendable. */
export const DEFAULT_AUTHORIZATION_TTL_MS = 300_000;

export function grant(
  session: SessionStore,
  binding: { credentialId: string; digests: string[] },
  options: { data: unknown; ttlMs?: number },
  now: number,
): AuthorizationCompleted {
  const ttlMs = options.ttlMs ?? DEFAULT_AUTHORIZATION_TTL_MS;
  const reference = `sad_${randomBytes(24).toString("base64url")}`;
  const sad: Sad = {
    credentialId: binding.credentialId,
    digests: binding.digests,
    expiresAt: now + ttlMs,
    data: options.data,
  };
  session.put(`sad:${reference}`, sad, ttlMs);
  return { kind: "authorization", reference, expiresAt: new Date(now + ttlMs).toISOString() };
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  const left = [...a].sort();
  const right = [...b].sort();
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function spend<T>(session: SessionStore, request: SignRequest, guard: Guard<T>, now: number): SpendResult<T> {
  // Taken in one step: a second `sign` with the same reference finds nothing, whatever happened to the first.
  const stored = session.take(`sad:${request.authorizationReference}`);
  const data: unknown = isSad(stored) ? (stored as { data?: unknown }).data : undefined;
  if (!isSad(stored) || !guard(data)) {
    return { ok: false, failure: failed("authorization_expired", "unknown or already-spent authorization reference") };
  }
  if (stored.expiresAt <= now) {
    return { ok: false, failure: failed("authorization_expired", "authorization expired") };
  }
  if (stored.credentialId !== request.credentialId) {
    return { ok: false, failure: failed("access_denied", "authorization was issued for a different credential") };
  }
  if (
    !sameSet(
      stored.digests,
      request.digests.map((digest) => digest.value),
    )
  ) {
    return { ok: false, failure: failed("digest_rejected", "digests differ from the authorized set") };
  }
  return { ok: true, data };
}
