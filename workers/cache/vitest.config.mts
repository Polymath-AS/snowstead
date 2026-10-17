import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

// One fresh database per run on the server HELIOS_TEST_DATABASE_URL names
// (scripts/with-postgres.sh starts one). test/global-setup.ts creates and
// migrates it; the Worker reaches it through the Hyperdrive binding's local
// connection string, as `wrangler dev` does.
const server = process.env.HELIOS_TEST_DATABASE_URL;
if (!server) {
	throw new Error('HELIOS_TEST_DATABASE_URL is not set: run the tests through scripts/with-postgres.sh (pnpm test does)');
}
const database = new URL(server);
database.pathname = `/helios_test_${process.pid}`;
process.env.HELIOS_TEST_DATABASE = database.toString();
process.env.CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE = database.toString();

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: './wrangler.jsonc' },
			miniflare: {
				bindings: {
					AUTH_TOKEN: "test-auth-token",
					ADMIN_SECRET: "test-admin-secret",
				},
			},
		}),
	],
	test: {
		globalSetup: ['./test/global-setup.ts'],
		// Files share the database, and GC sweeps all of it.
		fileParallelism: false,
	},
});
