import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { serve } from "@hono/node-server";
import { ConfigError, loadConfig } from "./config.ts";
import { JwksCache } from "./protocol/jwt.ts";
import { createWorker } from "./protocol/operations.ts";
import { openStore } from "./protocol/store.ts";
import { providerFromEnv } from "./providers/index.ts";

/** Entry point: configuration from the environment, one SQLite file, one HTTP listener. */
function main(): void {
  const config = loadConfig();
  const provider = providerFromEnv(config.provider, process.env);
  if (config.databasePath !== ":memory:") {
    mkdirSync(dirname(config.databasePath), { recursive: true });
  }
  const store = openStore(config.databasePath);
  const app = createWorker({
    provider,
    store,
    jwks: new JwksCache(config.platformJwksUrl),
    issuer: config.platformIssuer,
    publicUrl: config.publicUrl,
    connectionTokens: config.connectionTokens,
  });
  const sweeper = setInterval(() => store.sweep(), 10 * 60 * 1000);
  sweeper.unref();

  const server = serve({ fetch: app.fetch, port: config.port }, ({ port }) => {
    console.log(`swp worker (${provider.name}) listening on :${port}, public URL ${config.publicUrl}`);
  });
  const shutdown = () => {
    clearInterval(sweeper);
    server.close(() => {
      store.close();
      process.exit(0);
    });
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

try {
  main();
} catch (error) {
  console.error(error instanceof ConfigError || error instanceof Error ? error.message : String(error));
  process.exit(1);
}
