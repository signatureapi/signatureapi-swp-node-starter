/**
 * Worker configuration, from the environment. Provider-specific variables are read by the
 * provider's own folder (`src/providers/<name>/index.ts`), so deleting a provider deletes its config.
 */

export type Config = {
  port: number;
  /** The URL SignatureAPI calls this worker at, no trailing slash. It is the only accepted JWT `aud`. */
  publicUrl: string;
  platformIssuer: string;
  platformJwksUrl: string;
  /** The `swpct_…` tokens of the accounts this worker serves (dashboard › Qualified Signatures). */
  connectionTokens: string[];
  databasePath: string;
  provider: string;
};

export class ConfigError extends Error {}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) {
    throw new ConfigError(`${name} is required`);
  }
  return value;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const publicUrl = required(env, "PUBLIC_URL").replace(/\/+$/, "");
  if (!/^https?:\/\/[^/?#]+(\/[^?#]*)?$/.test(publicUrl)) {
    throw new ConfigError("PUBLIC_URL must be an absolute http(s) URL without query or fragment");
  }
  // Required on purpose: without a list, any SignatureAPI account that learns this URL could bind
  // it and send signing requests to your rail.
  const connectionTokens = required(env, "SIGNATUREAPI_CONNECTION_TOKENS")
    .split(",")
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
  if (connectionTokens.length === 0) {
    throw new ConfigError("SIGNATUREAPI_CONNECTION_TOKENS must list at least one connection token");
  }
  const port = Number(env.PORT ?? "8080");
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new ConfigError("PORT must be an integer port number");
  }
  return {
    port,
    publicUrl,
    platformIssuer: env.PLATFORM_ISSUER?.trim() || "https://api.signatureapi.com",
    platformJwksUrl: env.PLATFORM_JWKS_URL?.trim() || "https://api.signatureapi.com/v1/signing-protocol/jwks",
    connectionTokens,
    databasePath: env.DATABASE_PATH?.trim() || "./data/worker.sqlite",
    provider: required(env, "PROVIDER"),
  };
}
