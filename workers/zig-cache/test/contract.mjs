import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import test from 'node:test';

const require = createRequire(import.meta.url);
const wrangler = createRequire(require.resolve('wrangler'));
const { Miniflare, convertV4MiniflareOptions } = wrangler('miniflare');
const { build } = wrangler('esbuild');
const source = fileURLToPath(new URL('../src/index.ts', import.meta.url));
const bundled = await build({ entryPoints: [source], bundle: true, format: 'esm', write: false });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

test('isolated snapshot storage: private/public reads, immutable trusted writes, integrity, CDN auth', async () => {
  for (const publicRead of ['false', 'true']) {
    const mf = new Miniflare(convertV4MiniflareOptions({ workers: [{
      name: 'zig-test', script: bundled.outputFiles[0].text, modules: true,
      compatibilityDate: '2026-03-10', r2Buckets: ['ARTIFACTS'],
      bindings: { CACHE_NAMESPACE: 'test', READ_TOKEN: 'reader', WRITE_TOKEN: 'writer', PUBLIC_READ: publicRead },
    }] }));
    try {
      const key = `http://example.test/v1/snapshots/${hash('identity')}`;
      const put = (bytes, token = 'writer', digest = hash(bytes)) => mf.dispatchFetch(key, {
        method: 'PUT', body: bytes, headers: { authorization: `Bearer ${token}`, 'x-snapshot-sha256': digest, 'content-length': String(Buffer.byteLength(bytes)) },
      });
      assert.equal((await put('body', 'reader')).status, 403);
      assert.equal((await put('body', '', hash('body'))).status, 403);
      assert.equal((await put('corrupt', 'writer', hash('other'))).status, 400);
      const race = await Promise.all([put('body'), put('different')]);
      assert.deepEqual(race.map(r => r.status).sort(), [201, 409]);
      const res = await mf.dispatchFetch(key, { headers: { authorization: 'Bearer reader' } });
      assert.equal(res.status, 200);
      const bytes = await res.text();
      assert.equal(hash(bytes), res.headers.get('x-snapshot-sha256'));
      assert.equal(res.headers.get('cache-control'), 'no-store');
      assert.equal((await put(bytes)).status, 204);
      const warm = await mf.dispatchFetch(key, { headers: { authorization: 'Bearer reader' } });
      assert.equal(warm.headers.get('x-snowstead-cache'), 'HIT');
      await warm.arrayBuffer();
      const anonymous = await mf.dispatchFetch(key);
      assert.equal(anonymous.status, publicRead === 'true' ? 200 : 403);
      await anonymous.arrayBuffer();
      assert.equal((await mf.dispatchFetch(key.replace('/snapshots/', '/actions/'))).status, 404);
      assert.equal((await mf.dispatchFetch(key.replace(hash('identity'), hash('missing')), { headers: { authorization: 'Bearer reader' } })).status, 404);
    } finally { await mf.dispose(); }
  }
});
