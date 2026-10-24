import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { builtinModules } from 'node:module';
import { defineConfig } from 'vitest/config';

// One fresh database per run on the server SNOWSTEAD_TEST_DATABASE_URL names
// (scripts/with-postgres.sh starts one). test/global-setup.ts creates and
// migrates it; the Worker reaches it through the Hyperdrive binding's local
// connection string, as `wrangler dev` does.
const server = process.env.SNOWSTEAD_TEST_DATABASE_URL;
if (!server) {
	throw new Error('SNOWSTEAD_TEST_DATABASE_URL is not set: run the tests through scripts/with-postgres.sh (pnpm test does)');
}
const database = new URL(server);
database.pathname = `/snowstead_test_${process.pid}`;
process.env.SNOWSTEAD_TEST_DATABASE = database.toString();
process.env.CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE = database.toString();
// The repository's .env (beside the root wrangler.jsonc) holds deploy
// credentials, not Worker variables: keep it out of the test Worker.
process.env.CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV = 'false';

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: '../../wrangler.jsonc' },
			miniflare: {
				bindings: {
					AUTH_TOKEN: "test-auth-token",
					ADMIN_SECRET: "test-admin-secret",
					JWT_SECRET: "test-jwt-secret-0123456789abcdef",
					SIGNING_MASTER_KEY: "dGVzdC1zaWduaW5nLW1hc3Rlci1rZXktMzItYnl0ZXM=",
					// Legacy self-hosted fixtures opt in to shared keys explicitly.
					REQUIRE_CACHE_SIGNING_KEYS: "false",
					// Public, deterministic test-only seed; never depend on .dev.vars.
					SIGNING_PRIVATE_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
					SIGNING_KEY_NAME: "snowstead-1",
					// No upstream: tests never reach the network. test/upstream.spec.ts
					// checks one with a stand-in fetch.
					UPSTREAM_CACHES: "",
				},
			},
		}),
	],
	test: {
		globalSetup: ['./test/global-setup.ts'],
		// Bundle pg's CommonJS dependency graph for the Workers module loader.
		deps: {
			optimizer: {
				ssr: {
					enabled: true,
					include: ['pg'],
					rolldownOptions: { external: [...builtinModules, /^node:/] },
				},
			},
		},
		// Files share the database, and GC sweeps all of it.
		fileParallelism: false,
	},
});
