import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: './wrangler.jsonc' },
    miniflare: {
      bindings: {
        READ_TOKEN: 'test-reader-secret',
        WRITE_TOKEN: 'test-writer-secret',
        CACHE_NAMESPACE: 'test-go',
        RETENTION_SECONDS: '604800',
      },
    },
  })],
});
