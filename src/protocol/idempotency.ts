import type { SessionStore } from "./store.ts";

/**
 * SWP/1 §7, the Idempotency-Key rules:
 *
 * - Storage: only an outcome that is terminal for the act is stored (`completed`, or `failed` with
 *   `retryable: false`). `pending` and retryable failures are never stored, so a poll (the same
 *   operation, same envelope, same key) re-executes and is answered from current state.
 * - Replay: a stored outcome is replayed byte for byte. The retry of a `sign` that already happened
 *   gets the stored signatures and nothing signs twice.
 * - Conflict: the same key with a different body, or a key that is executing right now, is 409
 *   `idempotency_conflict`.
 * - Reservation: a key is reserved while it executes, and its outcome is stored before the
 *   reservation is released, so a retry landing in between can never run the act a second time.
 */

/** What the worker answers: an HTTP status and the exact JSON bytes. */
export type WireOutcome = { status: number; body: string };

type Stored = { bodySha256: string; outcome: WireOutcome };

/** Validated on read: a row that is not this shape reads as "not stored" and the act re-executes. */
function isStored(value: unknown): value is Stored {
  const row = value as Partial<Stored> | null;
  return (
    typeof row === "object" &&
    row !== null &&
    typeof row.bodySha256 === "string" &&
    typeof row.outcome?.status === "number" &&
    typeof row.outcome.body === "string"
  );
}

/**
 * Keys executing right now, in this process. In memory on purpose: a crash releases every
 * reservation, where a reservation row in the database would outlive the process and answer 409
 * until it expired. One process per database is the deployment model (README, "Scaling").
 */
const inFlight = new Set<string>();

export function isTerminal(outcome: WireOutcome): boolean {
  if (outcome.status !== 200) {
    return false;
  }
  const parsed = JSON.parse(outcome.body) as { status?: string; retryable?: boolean };
  return parsed.status === "completed" || (parsed.status === "failed" && parsed.retryable !== true);
}

function conflict(description: string): WireOutcome {
  return { status: 409, body: JSON.stringify({ error: "idempotency_conflict", error_description: description }) };
}

export async function withIdempotency(input: {
  store: SessionStore;
  sessionId: string;
  key: string;
  bodySha256: string;
  execute: () => Promise<WireOutcome>;
}): Promise<WireOutcome> {
  const storedKey = `idem:${input.key}`;
  const stored = input.store.get(storedKey);
  if (isStored(stored)) {
    return stored.bodySha256 === input.bodySha256
      ? stored.outcome
      : conflict(`Idempotency-Key ${input.key} was used with a different payload`);
  }
  const reservation = `${input.sessionId}\u0000${input.key}`;
  if (inFlight.has(reservation)) {
    return conflict(`Idempotency-Key ${input.key} is currently executing`);
  }
  inFlight.add(reservation);
  try {
    const outcome = await input.execute();
    if (isTerminal(outcome)) {
      input.store.put(storedKey, { bodySha256: input.bodySha256, outcome } satisfies Stored);
    }
    return outcome;
  } finally {
    inFlight.delete(reservation);
  }
}
