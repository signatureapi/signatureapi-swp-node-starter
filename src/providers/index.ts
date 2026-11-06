import { byoFromEnv } from "./byo/index.ts";
import { eidEasyFromEnv } from "./eideasy/index.ts";
import type { Provider } from "./types.ts";

/**
 * The providers this worker can run, chosen by `PROVIDER`. To add one, create
 * `src/providers/<name>/index.ts` exporting a factory and register it here. To drop one, delete its
 * folder and its line below.
 */
const providers: Record<string, (env: NodeJS.ProcessEnv) => Provider> = {
  byo: byoFromEnv,
  eideasy: eidEasyFromEnv,
};

export function providerFromEnv(name: string, env: NodeJS.ProcessEnv): Provider {
  const factory = providers[name];
  if (!factory) {
    throw new Error(`PROVIDER must be one of: ${Object.keys(providers).join(", ")} (got ${name})`);
  }
  return factory(env);
}
