import type {
  AuthorizeRequest,
  CredentialRequest,
  Digest,
  Failure,
  SignatureFormat,
  SignRequest,
} from "../providers/types.ts";
import { failed, OID } from "../providers/types.ts";

/**
 * The SWP/1 request envelope (§4) plus each operation's fields (§5), validated once and mapped to
 * the camelCase request a provider reads. Structural faults are 400 `invalid_request`; faults a rail
 * could act on are business failures (HTTP 200 `failed`), exactly as the reference worker answers.
 */

export const OPERATIONS = ["credential", "authorize", "sign"] as const;
export type Operation = (typeof OPERATIONS)[number];

export function isOperation(value: string): value is Operation {
  return (OPERATIONS as readonly string[]).includes(value);
}

/** Platform ids are `sgs_…`. A dot is reserved: tickets are `<sessionId>.<random>`. */
const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;
/** One envelope's worth of documents; more is a malformed request. */
export const MAX_DIGESTS = 50;
const DIGEST_LENGTH = new Map<string, number>([
  [OID.sha256, 32],
  [OID.sha384, 48],
  [OID.sha512, 64],
]);

export type RequestFor<O extends Operation> = O extends "credential"
  ? CredentialRequest
  : O extends "authorize"
    ? AuthorizeRequest
    : SignRequest;

/** `invalid` answers HTTP 400; `failure` answers HTTP 200 with that business failure. */
export type Rejection = { invalid: string } | { failure: Failure };
export type Parsed<O extends Operation> = { ok: true; request: RequestFor<O> } | { ok: false; rejection: Rejection };
type Json = Record<string, unknown>;

function isJson(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** The session id as the body names it, when it is one this worker can key storage by. */
export function sessionIdOf(body: Json): string | null {
  const session = isJson(body.session) ? body.session : {};
  return nonEmpty(session.id) && SESSION_ID.test(session.id) ? session.id : null;
}

function decodeBase64(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
    return null;
  }
  return Buffer.from(value, "base64");
}

function parseDigests(value: unknown): Digest[] | Rejection {
  if (!Array.isArray(value) || value.length === 0) {
    return { failure: failed("digest_rejected", "no digests supplied") };
  }
  if (value.length > MAX_DIGESTS) {
    return { invalid: `too many digests (max ${MAX_DIGESTS})` };
  }
  const digests: Digest[] = [];
  for (const entry of value) {
    if (!isJson(entry) || !nonEmpty(entry.value) || !nonEmpty(entry.hash_algorithm_oid)) {
      return { failure: failed("digest_rejected", "malformed digest entry") };
    }
    const length = DIGEST_LENGTH.get(entry.hash_algorithm_oid);
    if (length === undefined) {
      return { invalid: `unsupported hash_algorithm_oid ${entry.hash_algorithm_oid}` };
    }
    const bytes = decodeBase64(entry.value);
    if (bytes === null || bytes.length !== length) {
      return { invalid: `digest is not ${length} bytes of base64 for ${entry.hash_algorithm_oid}` };
    }
    digests.push({
      value: entry.value,
      bytes,
      hashAlgorithmOid: entry.hash_algorithm_oid,
      ...(nonEmpty(entry.label) ? { label: entry.label } : {}),
    });
  }
  return digests;
}

export function parseEnvelope<O extends Operation>(body: Json, operation: O): Parsed<O> {
  const parsed = parseFields(body, operation);
  return "invalid" in parsed || "failure" in parsed
    ? { ok: false, rejection: parsed }
    : { ok: true, request: parsed as RequestFor<O> };
}

function parseFields(body: Json, operation: Operation): CredentialRequest | AuthorizeRequest | SignRequest | Rejection {
  if (body.protocol !== "swp/1") {
    return { invalid: "unexpected protocol" };
  }
  const sessionId = sessionIdOf(body);
  if (sessionId === null) {
    return { invalid: "session.id is missing or invalid" };
  }
  const session = body.session as Json;
  const attempt = typeof session.attempt === "number" && session.attempt >= 1 ? session.attempt : 1;
  const signer = body.signer;
  // `email` may be "" (a recipient delivered by link has none), but it is always a string.
  if (!isJson(signer) || !nonEmpty(signer.id) || !nonEmpty(signer.name) || typeof signer.email !== "string") {
    return { invalid: "signer.id, signer.name and signer.email are required" };
  }
  if (!nonEmpty(body.scheme)) {
    return { invalid: "scheme is required" };
  }
  if (!nonEmpty(body.callback_url)) {
    return { invalid: "callback_url is required" };
  }
  const callback = body.callback;
  const callbackCode = isJson(callback) && nonEmpty(callback.code) ? callback.code : undefined;
  const base: CredentialRequest = {
    session: { id: sessionId, attempt },
    scheme: body.scheme,
    signer: { id: signer.id, name: signer.name, email: signer.email },
    callbackUrl: body.callback_url,
    ...(callbackCode === undefined ? {} : { callbackCode }),
  };
  if (operation === "credential") {
    return base;
  }

  // Digests are unconditional on authorize (the resume leg repeats them) and on sign.
  const digests = parseDigests(body.digests);
  if (!Array.isArray(digests)) {
    return digests;
  }
  if (!nonEmpty(body.credential_id)) {
    return { invalid: "credential_id is required" };
  }
  if (operation === "authorize") {
    return { ...base, credentialId: body.credential_id, digests };
  }

  const authorization = body.authorization;
  if (!isJson(authorization) || !nonEmpty(authorization.reference)) {
    return { failure: failed("authorization_expired", "authorization.reference is required") };
  }
  // Absent means `raw`, the format every worker spoke before `cms` existed.
  const format = body.signature_format ?? "raw";
  if (format !== "raw" && format !== "cms") {
    return { invalid: "signature_format must be raw or cms" };
  }
  if (format === "raw" && !nonEmpty(body.sign_algo_oid)) {
    return { invalid: "sign_algo_oid is required" };
  }
  if (body.sign_algo_oid !== undefined && !nonEmpty(body.sign_algo_oid)) {
    return { invalid: "sign_algo_oid must be a non-empty string" };
  }
  const request: SignRequest = {
    ...base,
    credentialId: body.credential_id,
    digests,
    authorizationReference: authorization.reference,
    signatureFormat: format satisfies SignatureFormat,
    ...(body.sign_algo_oid === undefined ? {} : { signAlgoOid: body.sign_algo_oid as string }),
  };
  return request;
}
