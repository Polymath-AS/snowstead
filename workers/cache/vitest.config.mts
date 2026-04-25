import path from 'node:path';
import { defineWorkersConfig, readD1Migrations } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig(async () => {
	const migrationsPath = path.join(import.meta.dirname, 'migrations');
	const migrations = await readD1Migrations(migrationsPath);

	return {
		test: {
			setupFiles: ['./test/apply-migrations.ts'],
			poolOptions: {
				workers: {
					wrangler: { configPath: './wrangler.jsonc' },
					miniflare: {
						bindings: {
							TEST_MIGRATIONS: migrations,
							AUTH_TOKEN: "test-auth-token",
						},
					},
				},
			},
		},
	};
});
