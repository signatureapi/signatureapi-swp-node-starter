import { DatabaseSync } from "node:sqlite";

/**
 * Everything the worker remembers, keyed by session: spent `jti`s, idempotency outcomes, tickets,
 * codes, authorizations and provider state. One SQLite file (`DATABASE_PATH`), one process.
 *
 * `node:sqlite` is synchronous, so every method below runs to completion without yielding: a
 * check-and-set such as `insertIfAbsent` or `take` is atomic inside this process. Running several
 * instances against one file, or against separate files behind a load balancer, breaks that; see
 * "Scaling" in the README.
 *
 * Every row carries an expiry. Expired rows read as absent and are swept periodically.
 */
export interface SessionStore {
  get(key: string): unknown;
  put(key: string, value: unknown, ttlMs?: number): void;
  /** Writes only when no live row exists. True when this call wrote it. */
  insertIfAbsent(key: string, value: unknown, ttlMs?: number): boolean;
  /** Reads and deletes in one step. Only the first caller gets the value. */
  take(key: string): unknown;
  delete(key: string): boolean;
}

export interface Store {
  session(sessionId: string): SessionStore;
  sweep(): number;
  close(): void;
}

/** How long a session's rows live by default. A signing session is minutes; a day is generous. */
export const DEFAULT_RETENTION_MS = 24 * 60 * 60 * 1000;

export function openStore(path: string, now: () => number = Date.now): Store {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS entries (
      session    TEXT    NOT NULL,
      key        TEXT    NOT NULL,
      value      TEXT    NOT NULL,
      expires_at INTEGER NOT NULL,
      PRIMARY KEY (session, key)
    ) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS entries_expiry ON entries (expires_at);
  `);
  const select = db.prepare("SELECT value FROM entries WHERE session = ? AND key = ? AND expires_at > ?");
  const upsert = db.prepare(
    "INSERT INTO entries (session, key, value, expires_at) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT (session, key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at",
  );
  const remove = db.prepare("DELETE FROM entries WHERE session = ? AND key = ?");
  const removeExpired = db.prepare("DELETE FROM entries WHERE expires_at <= ?");

  function read(session: string, key: string): unknown {
    const row = select.get(session, key, now()) as { value: string } | undefined;
    if (row === undefined) {
      return undefined;
    }
    try {
      return JSON.parse(row.value);
    } catch {
      return undefined;
    }
  }

  function write(session: string, key: string, value: unknown, ttlMs = DEFAULT_RETENTION_MS): void {
    upsert.run(session, key, JSON.stringify(value), now() + ttlMs);
  }

  return {
    session(sessionId) {
      return {
        get: (key) => read(sessionId, key),
        put: (key, value, ttlMs) => write(sessionId, key, value, ttlMs),
        insertIfAbsent(key, value, ttlMs) {
          if (read(sessionId, key) !== undefined) {
            return false;
          }
          write(sessionId, key, value, ttlMs);
          return true;
        },
        take(key) {
          const value = read(sessionId, key);
          if (value !== undefined) {
            remove.run(sessionId, key);
          }
          return value;
        },
        delete: (key) => Number(remove.run(sessionId, key).changes) > 0,
      };
    },
    sweep: () => Number(removeExpired.run(now()).changes),
    close: () => db.close(),
  };
}
