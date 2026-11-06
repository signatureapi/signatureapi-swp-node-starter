# SignatureAPI signing worker starter (Node.js)

A signing worker connects SignatureAPI qualified signatures to the signing service you choose. SignatureAPI computes the document digest; your worker gets it signed and returns the signature. The two sides talk SWP/1, a small HTTPS protocol with three operations: `credential`, `authorize` and `sign`.

This starter is a complete SWP/1 worker in plain, readable TypeScript. The protocol plumbing (request authentication, idempotency, the single-use authorization, browser hand-offs) lives in `src/protocol`. Each signing service is a **provider** in its own folder under `src/providers`, and `PROVIDER` picks one:

| Provider  | What it does                                                                                                                                                                  | Signature format |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| `byo`     | Signs with a P-256 key and certificate you supply, after the signer approves on a consent page. The template for a key in an HSM, a cloud KMS, or a provider's sign-hash API. | `raw`            |
| `eideasy` | Sends the signer to [eID Easy](https://eideasy.com) (Smart-ID, Mobile-ID, national eID cards and more) and returns the CMS eID Easy builds.                                   | `cms`            |

Delete the provider folders you don't use, and their line in `src/providers/index.ts`.

## Quick start

Requires Node.js 24 or newer.

```bash
npm ci
mkdir -p certs
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out certs/key.pem
openssl req -new -x509 -key certs/key.pem -out certs/chain.pem -days 30 -subj "/CN=Test signer"
cp .env.example .env
npm run dev
curl http://localhost:8080/v1/health
```

`npm run dev` reads `.env` and restarts on changes. `npm start` reads the real environment only.

Checks: `npm run lint`, `npm run typecheck`, `npm test`.

## Configuration

| Variable                                             | Required  | Meaning                                                                                                                                                                                          |
| ---------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `PROVIDER`                                           | yes       | `byo` or `eideasy`.                                                                                                                                                                              |
| `PUBLIC_URL`                                         | yes       | The URL SignatureAPI calls the worker at, exactly as you enter it in the dashboard. It is the only accepted JWT `aud`, so a trailing-slash difference fails every request with `unexpected aud`. |
| `SIGNATUREAPI_CONNECTION_TOKENS`                     | yes       | Comma-separated `swpct_…` tokens of the accounts this worker serves. The worker refuses to start without one.                                                                                    |
| `PORT`                                               | no        | Listening port. Default `8080`.                                                                                                                                                                  |
| `DATABASE_PATH`                                      | no        | SQLite file for worker state. Default `./data/worker.sqlite`.                                                                                                                                    |
| `PLATFORM_ISSUER`                                    | no        | Default `https://api.signatureapi.com`.                                                                                                                                                          |
| `PLATFORM_JWKS_URL`                                  | no        | Default `https://api.signatureapi.com/v1/signing-protocol/jwks`.                                                                                                                                 |
| `BYO_CERTIFICATES_PEM` / `BYO_CERTIFICATES_PEM_FILE` | `byo`     | Certificate chain, leaf first, as PEM text or a file path.                                                                                                                                       |
| `BYO_PRIVATE_KEY_PEM` / `BYO_PRIVATE_KEY_PEM_FILE`   | `byo`     | The leaf's P-256 private key (PKCS#8 PEM). The worker checks it matches the leaf.                                                                                                                |
| `EIDEASY_CLIENT_ID`, `EIDEASY_SECRET`                | `eideasy` | API credentials from eID Easy.                                                                                                                                                                   |
| `EIDEASY_BASE_URL`                                   | no        | Default `https://test.eideasy.com` (the sandbox). Production: `https://id.eideasy.com`.                                                                                                          |

## Connect to SignatureAPI

1. Deploy the worker at a public HTTPS URL on port 443 and set `PUBLIC_URL` to it.
2. In the dashboard, open **Settings › Qualified Signatures**. Copy the **Connection token** for the mode you are connecting (test and live tokens differ) into `SIGNATUREAPI_CONNECTION_TOKENS`, and restart the worker.
3. Choose **Connect**, enter the worker URL, and choose **Check and Connect**. SignatureAPI checks the URL, calls `GET /v1/health`, confirms the health response lists your connection token, and sends a signed probe that the worker must refuse for its missing `Idempotency-Key`. Nothing is saved unless every check passes.

## How it works

```
src/
  server.ts            entry point: config, SQLite, HTTP listener
  config.ts            environment
  protocol/            SWP/1, the same for every provider
    authenticate.ts    JWT + connection token + Content-Digest, in the protocol's order
    jwt.ts             ES256 verification and the platform key set
    envelope.ts        request validation, snake_case → camelCase
    idempotency.ts     Idempotency-Key: replay, 409, in-flight reservation
    operations.ts      routes, provider context, provider outcome → wire
    authorization.ts   the single-use authorization (grant / spend)
    handoff.ts         tickets, codes, browser pages
    store.ts           node:sqlite storage
  providers/
    types.ts           the provider interface and outcome builders
    index.ts           PROVIDER → provider
    byo/  eideasy/     one folder per provider
```

The protocol layer runs these checks on every operation, in this order: protocol header, JSON body, session id, bearer token, JWT (signature, `iss`, `aud`, `exp`, `iat`, unseen `jti`, operation, body hash), connection token, token-to-session binding, `Content-Digest`, then `Idempotency-Key`. Only then does it call the provider.

## Write your own provider

Create `src/providers/<name>/index.ts` that returns a `Provider`, and register it in `src/providers/index.ts`:

```ts
export interface Provider {
  readonly name: string; // reported by GET /v1/health as `rail`
  readonly format: SignatureFormat; // "raw" | "cms"
  credential(ctx: Context<CredentialRequest>): Promise<CredentialOutcome>;
  authorize(ctx: AuthorizeContext): Promise<AuthorizeOutcome>;
  sign(ctx: SignContext): Promise<SignOutcome>;
  readonly pages?: Readonly<Record<`/${string}`, PageHandler>>; // must not start with /v1/
}
```

Answer with the builders from `src/providers/types.ts`:
- `credential.raw({ id, certificates, keyAlgoOids })` when you know the signer's certificate before signing, or `credential.cms({ id, maxSignatureSize? })` when your service builds the CMS and the certificate arrives with the signature.
- `pending({ actionUrl, pollAfter, expiresAt })` while the signer has something to do: `actionUrl` sends their browser somewhere, `pollAfter` asks SignatureAPI to call again.
- `ctx.grant({ data })` from `authorize` once the signer approved. `data` is yours (a document id, your service's authorization) and comes back from `ctx.spend(guard)` in `sign`.
- `signed.raw(signatures)` or `signed.cms(cmsList, certificates)` from `sign`.
- `failed(code, why)` for a final refusal. `failed.retryable` exists for `credential` and `authorize` only, when nothing was started; the types do not let `sign` return `pending` or a retryable failure.

The context also gives you:
- `ctx.request`: the validated request, camelCase (`credentialId`, `digests[].bytes`, `callbackCode`, …).
- `ctx.state.get / put / once(key, guard, create)`: per-session state. Every read is validated by a guard such as `is.object({ docId: is.string })`; a row that fails it reads as absent. Use `once` for anything that must happen a single time per session, because a poll calls the same operation again.
- `ctx.handoff.begin({ purpose, path, ttlMs })`: a ticketed URL on this worker for the signer's browser. `ctx.handoff.redeem(code, purpose)` spends the code SignatureAPI resumes with; `ctx.handoff.completed(purpose)` tells a poll that the page finished.
- In a page handler, `page.ticket(request, purpose)` gives the open ticket or a ready 404/410 page, and `page.complete(ticket)` retires it, mints its one code, and redirects to SignatureAPI.

Throwing from `credential` or `authorize` answers 503 and SignatureAPI retries. Throwing from `sign` answers a stored, non-retryable `internal_error`: once your service was asked to sign, nobody can prove it did not.

## Conformance

The black-box SWP/1 tester lives in the workspace repo, `signatureapi/swp-workers-examples` (`shared/conformance`). It plays SignatureAPI (serving its own JWKS) and the signer's browser, and runs the happy paths (redirect and poll) plus the security negatives. Run it against a local `PROVIDER=byo` worker:

```bash
PROVIDER=byo PUBLIC_URL=http://127.0.0.1:8080 PLATFORM_JWKS_URL=http://127.0.0.1:4455/jwks \
  SIGNATUREAPI_CONNECTION_TOKENS=swpct_local BYO_CERTIFICATES_PEM_FILE=certs/chain.pem \
  BYO_PRIVATE_KEY_PEM_FILE=certs/key.pem npm start &
node ../swp-workers-examples/shared/conformance/src/cli.ts --worker http://127.0.0.1:8080 --connection-token swpct_local
```

CI runs the same tester. Because the workspace repo is private, the `conformance` job needs a repository secret `SWP_WORKSPACE_TOKEN` with read access to `signatureapi/swp-workers-examples`. **The secret is not created yet**: until it is, the job skips with a warning, so a green run does not mean conformance ran.

## Deploy

The `Dockerfile` runs the sources directly on Node 24 (no build step) and keeps state on the `/data` volume:

```bash
docker build -t swp-worker .
docker run -p 8080:8080 -v swp-data:/data -v "$PWD/certs:/certs:ro" --env-file .env \
  -e BYO_CERTIFICATES_PEM_FILE=/certs/chain.pem -e BYO_PRIVATE_KEY_PEM_FILE=/certs/key.pem swp-worker
```

Docker's `--env-file` takes one `NAME=value` per line, so pass PEM material as files (as above) or as `-e` values.

Any platform that runs a container with a persistent volume works. Put TLS in front of it (the platform's load balancer or a reverse proxy) and set `PUBLIC_URL` to the HTTPS address.

### Scaling

The worker keeps state in one SQLite file and is designed to run as **one instance**. Signing traffic is light (a few requests per signature), so one instance goes a long way. To run several instances, every instance must see the same state and requests for one signing session must not run concurrently on two instances: move `src/protocol/store.ts` to a shared database with atomic check-and-set (for example Postgres), and route by session or replace the in-memory reservation in `src/protocol/idempotency.ts` with a database lock.

## Security notes

- **Connection tokens are required.** Without them, any SignatureAPI account that learns your URL could send signing requests to your service.
- **Request bodies contain personal data** (signer name and email). The worker never logs bodies; keep it that way in your provider.
- **`sign` signs once.** A repeated `sign` with the same `Idempotency-Key` replays the stored answer, and an authorization is spent by the first `sign` that presents it.
- **Browser pages** carry an unguessable ticket, mint exactly one code, and send restrictive headers. They allow framing on purpose, because SignatureAPI ceremonies can run inside an iframe.
- **`byo` is not a qualified signature.** A private key in an environment variable is not a qualified signature creation device. Use it to test, or as the template for a key held in an HSM or by a trust service provider.
- **Keep `DATABASE_PATH` private.** It holds authorizations and codes for the sessions in flight. Rows expire after a day and are swept every ten minutes.

## License

MIT
