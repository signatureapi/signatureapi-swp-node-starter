import "reflect-metadata";
import { createHash, generateKeyPairSync, randomUUID, sign as signBytes, webcrypto } from "node:crypto";
import {
  CertificateChoices,
  CertificateSet,
  ContentInfo,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  id_data,
  id_signedData,
  SignedData,
  SignerIdentifier,
  SignerInfo,
  SignerInfos,
} from "@peculiar/asn1-cms";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier, Certificate } from "@peculiar/asn1-x509";
import * as x509 from "@peculiar/x509";
import type { Hono } from "hono";
import { JwksCache } from "../src/protocol/jwt.ts";
import { createWorker } from "../src/protocol/operations.ts";
import { openStore, type Store } from "../src/protocol/store.ts";
import type { Provider } from "../src/providers/types.ts";

export const PUBLIC_URL = "http://worker.test";
export const ISSUER = "https://api.signatureapi.com";
export const CONNECTION_TOKEN = "swpct_0123456789abcdefghijklmnopqrstuv";
export const SHA256 = "2.16.840.1.101.3.4.2.1";

const platform = generateKeyPairSync("ec", { namedCurve: "P-256" });
const KID = "test-kid";
const jwks = { keys: [{ ...platform.publicKey.export({ format: "jwk" }), kid: KID, use: "sig", alg: "ES256" }] };

export function mintJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "ES256", kid: KID, typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = signBytes("sha256", Buffer.from(`${header}.${payload}`), {
    key: platform.privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${header}.${payload}.${signature.toString("base64url")}`;
}

export type TestWorker = {
  app: Hono;
  store: Store;
  clock: { now: number };
  logs: string[];
  call(operation: string, body: Record<string, unknown>, options?: CallOptions): Promise<Response>;
};

export type CallOptions = {
  claims?: Record<string, unknown>;
  headers?: Record<string, string | null>;
  /** Sent instead of the body the token and Content-Digest were computed over. */
  sentBody?: string;
  idempotencyKey?: string | null;
};

export function sha256(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("base64");
}

export function makeWorker(provider: Provider): TestWorker {
  const clock = { now: Date.now() };
  const store = openStore(":memory:", () => clock.now);
  const logs: string[] = [];
  const app = createWorker({
    provider,
    store,
    jwks: new JwksCache("http://platform.test/jwks", (async () => Response.json(jwks)) as typeof fetch),
    issuer: ISSUER,
    publicUrl: PUBLIC_URL,
    connectionTokens: [CONNECTION_TOKEN],
    now: () => clock.now,
    log: (message) => logs.push(message),
  });
  async function call(operation: string, body: Record<string, unknown>, options: CallOptions = {}) {
    const raw = JSON.stringify(body);
    const session = (body.session as { id?: string } | undefined)?.id;
    const iat = Math.floor(clock.now / 1000);
    const token = mintJwt({
      iss: ISSUER,
      aud: PUBLIC_URL,
      sub: "re_1",
      iat,
      exp: iat + 300,
      jti: randomUUID(),
      connection_token: CONNECTION_TOKEN,
      swp: { session, operation, body_sha256: sha256(raw) },
      ...options.claims,
    });
    const headers: Record<string, string> = {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
      "signatureapi-protocol": "swp/1",
      "content-digest": `sha-256=:${sha256(raw)}:`,
    };
    const key = options.idempotencyKey === undefined ? `${session}/${operation}/1` : options.idempotencyKey;
    if (key !== null) {
      headers["idempotency-key"] = key;
    }
    for (const [name, value] of Object.entries(options.headers ?? {})) {
      if (value === null) {
        delete headers[name];
      } else {
        headers[name] = value;
      }
    }
    return app.request(`/v1/${operation}`, { method: "POST", headers, body: options.sentBody ?? raw });
  }
  return { app, store, clock, logs, call };
}

export function envelope(sessionId: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    protocol: "swp/1",
    session: { id: sessionId, attempt: 1 },
    scheme: "eu_eidas",
    signer: { id: "re_1", name: "Ada Lovelace", email: "ada@example.com" },
    callback_url: "https://api.signatureapi.test/v1/signing-sessions/callback?state=abc",
    ...extra,
  };
}

export function digestOf(message: string, label = "Contract.pdf") {
  return { value: sha256(message), hash_algorithm_oid: SHA256, label };
}

/** Plays the signer's browser on a worker-hosted form: GET the page, POST its form, read the code. */
export async function submitConsent(app: Hono, actionUrl: string): Promise<{ status: number; code?: string }> {
  const page = await app.request(actionUrl);
  const html = await page.text();
  const ticket = /name="ticket" value="([^"]+)"/.exec(html)?.[1];
  const action = /<form method="post" action="([^"]+)"/.exec(html)?.[1];
  if (!ticket || !action) {
    return { status: page.status };
  }
  const posted = await app.request(`${PUBLIC_URL}${action}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ticket }).toString(),
  });
  const location = posted.headers.get("location");
  return { status: posted.status, ...(location ? { code: new URL(location).searchParams.get("code") ?? "" } : {}) };
}

// ------------------------------------------------------------------------------------------
// Test PKI: root → intermediate → P-256 leaf, plus an OCSP responder certificate.
// ------------------------------------------------------------------------------------------

const EC = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;
x509.cryptoProvider.set(webcrypto as unknown as Crypto);

async function issue(input: {
  subject: string;
  issuer?: { name: string; keys: CryptoKeyPair };
  ca: boolean;
  serial: string;
  ocsp?: boolean;
}) {
  const keys = (await webcrypto.subtle.generateKey(EC, true, ["sign", "verify"])) as CryptoKeyPair;
  const extensions: x509.Extension[] = [new x509.BasicConstraintsExtension(input.ca, undefined, true)];
  if (input.ocsp) {
    extensions.push(new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.ocspSigning]));
  }
  const certificate = await x509.X509CertificateGenerator.create({
    serialNumber: input.serial,
    subject: input.subject,
    issuer: input.issuer?.name ?? input.subject,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 365 * 864e5),
    publicKey: keys.publicKey,
    signingKey: (input.issuer?.keys ?? keys).privateKey,
    signingAlgorithm: EC,
    extensions,
  });
  const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  return {
    certificate,
    pem: certificate.toString("pem"),
    keys,
    privateKeyPem: x509.PemConverter.encode(pkcs8, "PRIVATE KEY"),
  };
}

export async function testPki() {
  const root = await issue({ subject: "CN=Test Root", ca: true, serial: "01" });
  const intermediate = await issue({
    subject: "CN=Test Intermediate",
    issuer: { name: "CN=Test Root", keys: root.keys },
    ca: true,
    serial: "02",
  });
  const leaf = await issue({
    subject: "CN=Ada Lovelace",
    issuer: { name: "CN=Test Intermediate", keys: intermediate.keys },
    ca: false,
    serial: "0a1b2c",
  });
  const ocsp = await issue({
    subject: "CN=Test OCSP",
    issuer: { name: "CN=Test Intermediate", keys: intermediate.keys },
    ca: false,
    serial: "03",
    ocsp: true,
  });
  return { root, intermediate, leaf, ocsp };
}

/** A detached CMS SignedData carrying only the leaf, shaped like eID Easy's (signature bytes are a stand-in). */
export function cmsWithLeaf(leaf: x509.X509Certificate): Uint8Array {
  const certificate = AsnConvert.parse(leaf.rawData, Certificate);
  const signedData = new SignedData({
    version: 1,
    encapContentInfo: new EncapsulatedContentInfo({ eContentType: id_data }),
    certificates: new CertificateSet([new CertificateChoices({ certificate })]),
    signerInfos: new SignerInfos([
      new SignerInfo({
        version: 1,
        sid: new SignerIdentifier({
          issuerAndSerialNumber: new IssuerAndSerialNumber({
            issuer: certificate.tbsCertificate.issuer,
            serialNumber: certificate.tbsCertificate.serialNumber,
          }),
        }),
        digestAlgorithm: new AlgorithmIdentifier({ algorithm: SHA256 }),
        signatureAlgorithm: new AlgorithmIdentifier({ algorithm: "1.2.840.10045.4.3.2" }),
        signature: new OctetString(new Uint8Array(64)),
      }),
    ]),
  });
  return new Uint8Array(
    AsnConvert.serialize(new ContentInfo({ contentType: id_signedData, content: AsnConvert.serialize(signedData) })),
  );
}
