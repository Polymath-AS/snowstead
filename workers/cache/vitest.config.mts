import path from 'node:path';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig(async () => {
	const migrationsPath = path.join(import.meta.dirname, 'migrations');
	const migrations = await readD1Migrations(migrationsPath);

	return {
		plugins: [
			cloudflareTest({
				wrangler: { configPath: './wrangler.jsonc' },
				miniflare: {
					bindings: {
						TEST_MIGRATIONS: migrations,
						AUTH_TOKEN: "test-auth-token",
					},
				},
			}),
		],
		test: {
			setupFiles: ['./test/apply-migrations.ts'],
		},
	};
});
