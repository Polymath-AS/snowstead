// nix develop --command node scripts/sccache-api-profile.mjs [artifact-label]
// Owns a disposable PostgreSQL cluster; never uses configured database URLs.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { request } from 'node:http';
import { createRequire } from 'node:module';
import { resolve, join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
const root = resolve(new URL('..', import.meta.url).pathname);
const require = createRequire(join(root, 'packages/cache-core/package.json'));
const { Client } = require('pg');
const { drizzle } = require('drizzle-orm/node-postgres');
const { migrate } = require('drizzle-orm/node-postgres/migrator');
const { createTestHarness } = require('wrangler');
const label = process.argv[2] ?? 'current';
assert(/^[a-z0-9-]+$/.test(label));
const entries = Number(process.env.PROFILE_ENTRIES ?? 0);
assert(Number.isSafeInteger(entries) && entries >= 0);
const expiryMinutes = Number(process.env.PROFILE_EXPIRY_MINUTES ?? 0);
assert(Number.isSafeInteger(expiryMinutes) && expiryMinutes >= 0);
execFileSync('git', ['check-ignore', '.amp/in/'], { cwd: root });
const out = join(root, '.amp/in/artifacts/sccache-api', label);
await mkdir(out, { recursive: true });
const temp = await mkdtemp(join(tmpdir(), 'snowstead-profile-'));
const port = await new Promise(resolve => {
  const socket = createServer().listen(0, '127.0.0.1', () => {
    const port = socket.address().port; socket.close(() => resolve(port));
  });
});
let server, db, started = false;
const results = [];
try {
  await writeFile(join(temp, 'pw'), 'postgres');
  execFileSync('initdb', ['-D', join(temp, 'data'), '-U', 'postgres', '--pwfile=' + join(temp, 'pw'), '--auth=scram-sha-256', '--no-sync']);
  execFileSync('pg_ctl', ['-D', join(temp, 'data'), '-l', join(temp, 'postgres.log'), '-w', '-o', `-p ${port} -k ${temp} -c listen_addresses=127.0.0.1 -c fsync=off -c max_connections=256 -c shared_preload_libraries=pg_stat_statements`, 'start']);
  started = true;
  const connectionString = `postgres://postgres:postgres@127.0.0.1:${port}/postgres`;
  db = new Client({ connectionString, application_name: 'profile-observer' }); await db.connect();
  await db.query('CREATE EXTENSION pg_stat_statements');
  await migrate(drizzle(db), { migrationsFolder: join(root, 'packages/cache-core/migrations') });
  process.env.CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE = connectionString;
  process.env.CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV = 'false';
  const secrets = { ADMIN_SECRET: 'profile-admin', JWT_SECRET: 'profile-jwt-0123456789abcdef', SIGNING_MASTER_KEY: 'dGVzdC1zaWduaW5nLW1hc3Rlci1rZXktMzItYnl0ZXM=' };
  const vars = { UPSTREAM_CACHES: '', CDN_ZONE_ID: '', PUBLIC_CACHE_ORIGIN: '' };
  server = createTestHarness({ root, workers: [{ configPath: 'wrangler.jsonc' }, ...['control', 'nix', 'go', 'sccache'].map(name => ({ configPath: `workers/${name}/wrangler.jsonc`, vars, secrets }))] });
  const { url } = await server.listen();
  async function api(path, body, method = 'POST') {
    const res = await fetch(new URL('/_api/v1/' + path, url), { method, headers: { authorization: 'Bearer profile-admin', 'content-type': 'application/json' }, body: JSON.stringify(body) });
    assert(res.ok, `${res.status} ${await res.clone().text()}`); return res.json();
  }
  await api('orgs/default', { storageLimit: entries * 65536 + 1024 ** 3 }, 'PUT');
  await api('admin/caches', { name: 'profile', private: true, protocols: ['sccache'] });
  if (entries) {
    // Metadata scale fixture, not a claim that this many payloads were uploaded.
    await db.query(`insert into sccache_entries (id, cache_id, generation, action, r2_key, size, uploaded_at, expires_at)
      select 'seed-' || i, c.id, c.sccache_generation, lpad(to_hex(10000000 + i), 64, '0'),
        'seed/' || i, 65536, now(), case when $2::int = 0 then now() + interval '7 days'
          else now() + interval '1 hour' + (i % $2::int) * interval '1 minute' end
      from caches c cross join generate_series(1, $1::int) i where c.name = 'profile' and c.org_id = 'default'`, [entries, expiryMinutes]);
    await db.query('ANALYZE caches; ANALYZE sccache_entries; ANALYZE sccache_usage');
  }
  const { token } = await api('admin/tokens', { subject: 'profile', caches: ['profile'], perms: ['sccache:read', 'sccache:write'] });
  const headers = { authorization: `Bearer ${token}` };
  const key = i => i.toString(16).padStart(64, '0');
  const endpoint = i => new URL(`/_api/v1/sccache/default/profile/${key(i).slice(0, 3).split('').join('/')}/${key(i)}`, url);
  const body = Buffer.alloc(64 * 1024, 42);
  async function call(i, method = 'GET', payload = body) {
    const response = await fetch(endpoint(i), { method, headers, body: method === 'PUT' ? payload : undefined });
    const data = await response.arrayBuffer();
    if (response.status === 200 && method === 'GET') assert(Buffer.from(data).equals(payload));
    return response.status;
  }
  function slowPut(i, delay = 1500) {
    return new Promise((resolve, reject) => {
      const req = request(endpoint(i), { method: 'PUT', headers: { ...headers, 'content-length': String(body.length) } }, res => {
        res.resume(); res.on('end', () => resolve(res.statusCode));
      });
      req.on('error', reject); req.write(body.subarray(0, 1));
      setTimeout(() => req.end(body.subarray(1)), delay);
    });
  }
  async function measure(name, count, concurrency, operation) {
    await sleep(100);
    await db.query('SELECT pg_stat_statements_reset()');
    let finished = false, next = 0;
    const samples = [], timings = [], statuses = {};
    const sampling = (async () => {
      while (!finished) {
        const { rows } = await db.query(`select count(*)::int as connections,
          count(*) filter(where state = 'active')::int as active,
          count(*) filter(where state = 'idle in transaction')::int as idle_in_transaction,
          count(*) filter(where wait_event_type = 'Lock')::int as lock_waits
          from pg_stat_activity where datname = current_database() and pid <> pg_backend_pid()`);
        samples.push({ ms: performance.now(), ...rows[0] }); await sleep(10);
      }
    })();
    const begin = performance.now();
    try {
      await Promise.all(Array.from({ length: concurrency }, async () => {
        for (;;) {
          const i = next++; if (i >= count) return;
          const start = performance.now(), status = await operation(i);
          timings.push(performance.now() - start); statuses[status] = (statuses[status] ?? 0) + 1;
        }
      }));
    } finally { finished = true; await sampling; }
    const wallMs = performance.now() - begin;
    const { rows: queries } = await db.query(`select query, calls::int, total_exec_time, mean_exec_time, rows::int
      from pg_stat_statements where dbid = (select oid from pg_database where datname = current_database())
      and query not like '%pg_stat_%' order by total_exec_time desc`);
    timings.sort((a,b) => a-b);
    const peak = field => Math.max(0, ...samples.map(s => s[field]));
    const result = { name, count, concurrency, statuses, wallMs, rps: count * 1000 / wallMs,
      p50Ms: timings[Math.floor(timings.length / 2)], p95Ms: timings[Math.ceil(timings.length * .95) - 1],
      statements: queries.reduce((n,q) => n + q.calls, 0), sqlExecutionMs: queries.reduce((n,q) => n + q.total_exec_time, 0),
      peakConnections: peak('connections'), peakActive: peak('active'), peakIdleTransaction: peak('idle_in_transaction'), peakLockWaits: peak('lock_waits') };
    results.push(result); console.log(JSON.stringify(result));
    await writeFile(join(out, name + '.json'), JSON.stringify({ result, queries, samples, timings }, null, 2));
    await writeFile(join(out, 'results.json'), JSON.stringify(results, null, 2));
    if (process.env.PROFILE_EXPLAIN && name.startsWith('cleanup')) {
      const plans = [];
      for (const { query } of queries.filter(q => q.query.includes('sccache_entries') && /for update/i.test(q.query))) {
        const params = Array(Math.max(...[...query.matchAll(/\$(\d+)/g)].map(m => Number(m[1])))).fill(500);
        for (const match of query.matchAll(/expires_at"?\s*(?:>|<=)\s*\$(\d+)/g)) params[Number(match[1]) - 1] = new Date();
        await db.query('BEGIN');
        try { plans.push({ query, plan: (await db.query('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' + query, params)).rows }); }
        finally { await db.query('ROLLBACK'); }
      }
      await writeFile(join(out, name + '-plans.json'), JSON.stringify(plans, null, 2));
    }
  }
  if (entries) {
    for (let repeat = 0; repeat < 3; repeat++) {
      await measure(`large-put-${repeat}`, 16, 1, i => call(repeat * 100 + i, 'PUT'));
      await measure(`large-burst-${repeat}`, 32, 8, i => call(repeat * 100 + 16 + i, 'PUT'));
      await measure(`large-read-${repeat}`, 32, 8, i => call(repeat * 100 + i));
      const usage = await api('orgs/default', undefined, 'GET');
      assert.equal(usage.used, (entries + (repeat + 1) * 48) * 65536);
      assert.equal(usage.pending, 0);
    }
    await writeFile(join(out, 'fixture.json'), JSON.stringify({ metadataEntries: entries, metadataBytes: entries * 65536, expiryMinutes, realUploads: 144 }));
    for (let repeat = 0; repeat < 3; repeat++) {
      await db.query(`insert into sccache_entries (id, cache_id, generation, action, r2_key, size, uploaded_at, expires_at)
        select 'garbage-' || i, c.id, c.sccache_generation, lpad(to_hex(20000000 + i), 64, '0'),
          'garbage/' || i, 1, now() - interval '8 days', now() - interval '1 day'
        from caches c cross join generate_series(1, 500) i where c.name = 'profile' and c.org_id = 'default'`);
      await measure(`cleanup-${repeat}`, 1, 1, async () => {
        await server.getWorker('snowstead-control').scheduled({ cron: '0 * * * *', scheduledTime: new Date() });
        return 200;
      });
      assert.equal(Number((await db.query("select count(*) from sccache_entries where id like 'garbage-%'")).rows[0].count), 0);
      assert.equal(Number((await db.query("select count(*) from sccache_entries where id like 'seed-%'")).rows[0].count), entries);
    }
    for (const kind of ['idle', 'detached', 'obsolete']) {
      for (let repeat = 0; repeat < 3; repeat++) {
        if (kind !== 'idle') await db.query(`insert into sccache_entries (id, cache_id, generation, action, r2_key, size, uploaded_at, expires_at)
          select 'extra-' || i, case when $1 = 'detached' then null else c.id end,
            case when $1 = 'obsolete' then 'obsolete' else c.sccache_generation end,
            lpad(to_hex(30000000 + i),64,'0'), 'extra/' || i, 0, now(), now() + interval '7 days'
          from caches c cross join generate_series(1,500) i where c.name='profile' and c.org_id='default'`, [kind]);
        await measure(`cleanup-${kind}-${repeat}`, 1, 1, async () => {
          await server.getWorker('snowstead-control').scheduled({ cron: '0 * * * *', scheduledTime: new Date() });
          return 200;
        });
        assert.equal(Number((await db.query("select count(*) from sccache_entries where id like 'extra-%'")).rows[0].count), 0);
        assert.equal(Number((await db.query("select count(*) from sccache_entries where id like 'seed-%'")).rows[0].count), entries);
      }
    }
    // Exercise the publication gate at capacity, not just its no-eviction path.
    const retained = (entries + 144) * 65536;
    await api('orgs/default', { storageLimit: retained }, 'PUT');
    for (let repeat = 0; repeat < 3; repeat++) {
      await measure(`capacity-put-${repeat}`, 16, 1, i => call(1000 + repeat * 100 + i, 'PUT'));
      assert.deepEqual(results.at(-1).statuses, { 201: 16 });
      const usage = await api('orgs/default', undefined, 'GET');
      assert.equal(usage.used, retained);
      assert.equal(usage.pending, 0);
      assert.equal(Number((await db.query('select count(*) from sccache_entries where cache_id is null')).rows[0].count), (repeat + 1) * 16);
    }
    if (process.env.PROFILE_MANY_VICTIMS) {
      const large = Buffer.alloc(4 * 1024 * 1024, 71);
      await measure('capacity-64-victims', 16, 1, i => call(5000 + i, 'PUT', large));
      assert.deepEqual(results.at(-1).statuses, { 201: 16 });
      assert.equal(Number((await db.query('select count(*) from sccache_entries where cache_id is null')).rows[0].count), 48 + 16 * 64);
      assert.equal((await api('orgs/default', undefined, 'GET')).used, retained);
      for (let i = 0; i < 16; i++) assert.equal(await call(5000 + i, 'GET', large), 200);
    }
  } else {
    await measure('miss', 32, 1, i => call(1000 + i));
    await measure('put', 32, 1, i => call(i, 'PUT'));
    await measure('duplicate', 32, 1, i => call(i, 'PUT'));
    await measure('hit', 32, 1, i => call(i));
    await measure('edge-hit', 32, 1, i => call(i));
    await measure('read-burst', 256, 64, i => call(i % 32));
    await measure('write-burst', 128, 64, i => call(2000 + i, 'PUT'));
    await measure('slow-writes', 64, 64, i => slowPut(3000 + i));
    await measure('overload', 96, 96, i => slowPut(4000 + i, 3000));
    await measure('recovery', 32, 8, i => call(i));
  }
  await writeFile(join(out, 'worker-logs.json'), JSON.stringify(server.getLogs(), null, 2));
} finally {
  await server?.close(); await db?.end();
  if (started) execFileSync('pg_ctl', ['-D', join(temp, 'data'), '-m', 'immediate', 'stop']);
  await rm(temp, { recursive: true, force: true });
}
