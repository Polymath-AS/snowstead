// Run from the repository root inside nix develop:
// scripts/with-postgres.sh node scripts/sccache-build-bench.mjs
// Builds pinned upstream releases; uses only a disposable local database/R2.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readFile, writeFile, rm, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);
const require = createRequire(join(root, 'packages/cache-core/package.json'));
const { Client } = require('pg');
const { drizzle } = require('drizzle-orm/node-postgres');
const { migrate } = require('drizzle-orm/node-postgres/migrator');
const { createTestHarness } = require('wrangler');
const jobs = Number(process.env.BENCH_JOBS ?? 12);
const repeats = Number(process.env.BENCH_REPEATS ?? 3);
assert(Number.isInteger(jobs) && jobs > 0 && Number.isInteger(repeats) && repeats > 0);
const sccache = process.env.BENCH_SCCACHE ?? 'sccache';
const work = join(root, '.amp/in/compiler-bench');
const artifacts = join(root, '.amp/in/artifacts/compiler-bench');
const baseEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
  !key.startsWith('SCCACHE_') && !['RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_TARGET_DIR', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CC', 'CXX', 'CFLAGS', 'CXXFLAGS'].includes(key)));
Object.assign(baseEnv, { CARGO_INCREMENTAL: '0', CARGO_BUILD_JOBS: String(jobs) });
for (const lib of ['SNAPPY', 'GFLAGS', 'ZLIB', 'BZIP', 'LZ4', 'ZSTD', 'NUMA', 'TBB', 'JEMALLOC', 'TCMALLOC', 'MEMKIND', 'BENCHMARK']) baseEnv[`ROCKSDB_DISABLE_${lib}`] = '1';

async function run(command, args, { cwd = root, env = baseEnv, log } = {}) {
  const output = log ? createWriteStream(join(artifacts, log)) : null;
  let stdout = '', stderr = '';
  const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', data => { if (output) output.write(data); else stdout += data; });
  child.stderr.on('data', data => { if (output) output.write(data); else stderr += data; });
  try {
    await new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('close', code => code === 0 ? resolve() : reject(new Error(`${command} exited ${code}; ${log ?? stderr}`)));
    });
  } finally { if (output) await new Promise(resolve => output.end(resolve)); }
  return stdout;
}
async function hash(path) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest('hex');
}
await run('git', ['check-ignore', '.amp/in/compiler-bench']);
await mkdir(work, { recursive: true });
await mkdir(artifacts, { recursive: true });
const projects = [
  { name: 'ripgrep', cache: 'rust', repo: 'https://github.com/BurntSushi/ripgrep.git', tag: '14.1.1', revision: '4649aa9700619f94cf9c66876e9549d83420e16c', output: 'target/release/rg' },
  { name: 'rocksdb', cache: 'cpp', repo: 'https://github.com/facebook/rocksdb.git', tag: 'v9.10.0', revision: 'ae8fb3e5000e46d8d4c9dbf3a36019c0aaceebff', output: 'librocksdb.a' },
];
for (const project of projects) {
  project.cwd = join(work, project.name);
  if (!await stat(project.cwd).catch(() => null)) await run('git', ['clone', '--depth', '1', '--branch', project.tag, project.repo, project.cwd]);
  assert.equal((await run('git', ['rev-parse', 'HEAD'], project)).trim(), project.revision);
  assert.equal(await run('git', ['diff', '--stat', 'HEAD'], project), '');
}
await run('cargo', ['fetch', '--locked'], { ...projects[0], log: 'fetch.log' });
await writeFile(join(work, 'sccache.toml'), '');
await writeFile(join(work, 'search.txt'), 'unmatched\ncompiler-cache-hit\nunmatched again\n');
await writeFile(join(work, 'smoke.cc'), `#include <cassert>
#include <string>
#include "rocksdb/db.h"
int main(int argc, char** argv) {
  assert(argc == 2);
  rocksdb::Options options; options.create_if_missing = true;
  rocksdb::DB* db = nullptr;
  assert(rocksdb::DB::Open(options, argv[1], &db).ok());
  assert(db->Put(rocksdb::WriteOptions(), "ci-key", "ci-value").ok());
  std::string value;
  assert(db->Get(rocksdb::ReadOptions(), "ci-key", &value).ok());
  assert(value == "ci-value"); delete db;
}
`);
// RocksDB 9.10 relied on a transitive cstdint include removed by GCC 15.
const makeArgs = ['-j' + jobs, 'static_lib', 'DEBUG_LEVEL=0', 'PORTABLE=1', 'DISABLE_WARNING_AS_ERROR=1', 'EXTRA_CXXFLAGS=-include cstdint'];
await writeFile(join(artifacts, 'method.json'), JSON.stringify({ jobs, repeats, projects, makeArgs,
  cargoArgs: ['build', '--release', '--locked', '--offline'],
  cases: ['uncached clean builds (median)', 'cold remote cache population (one run)', 'clean warm builds (median, fresh daemon/local cache each time)'],
  quotaBytes: 4 * 1024 ** 3, rustc: await run('rustc', ['--version']), cxx: await run('c++', ['--version']), sccache: await run(sccache, ['--version']),
  limitations: ['local workerd/R2/Postgres, no WAN', 'same checkout path', 'warm OS page cache, dependencies prefetched', 'RocksDB optional compression/allocator libraries disabled', 'build timing excludes clean/configuration, daemon startup, checks and downloads; includes compile, link/archive and remote upload drain'],
}, null, 2));

const database = new URL(process.env.SNOWSTEAD_TEST_DATABASE_URL);
const admin = new Client({ connectionString: database.href });
await admin.connect();
const dbName = `sccache_build_bench_${process.pid}`;
await admin.query(`CREATE DATABASE "${dbName}"`);
database.pathname = '/' + dbName;
let server, clientEnv, db;
const results = [];
try {
  db = new Client({ connectionString: database.href }); await db.connect();
  await migrate(drizzle(db), { migrationsFolder: join(root, 'packages/cache-core/migrations') });
  process.env.CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE = database.href;
  process.env.CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV = 'false';
  const secrets = { ADMIN_SECRET: 'compiler-bench-admin', JWT_SECRET: 'compiler-bench-jwt-0123456789abcdef', SIGNING_MASTER_KEY: 'dGVzdC1zaWduaW5nLW1hc3Rlci1rZXktMzItYnl0ZXM=' };
  const vars = { UPSTREAM_CACHES: '', CDN_ZONE_ID: '', PUBLIC_CACHE_ORIGIN: '' };
  server = createTestHarness({ root, workers: [{ configPath: 'wrangler.jsonc' }, ...['control', 'nix', 'go', 'sccache'].map(name => ({ configPath: `workers/${name}/wrangler.jsonc`, vars, secrets }))] });
  const { url } = await server.listen();
  async function api(path, body, method = 'POST') {
    const response = await fetch(new URL('/_api/v1/' + path, url), { method, headers: { authorization: 'Bearer compiler-bench-admin', 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    assert(response.ok, `${path}: ${response.status} ${await response.clone().text()}`);
    return response.json();
  }
  await api('orgs/default', { storageLimit: 4 * 1024 ** 3 }, 'PUT');
  for (const project of projects) {
    await api('admin/caches', { name: project.cache, private: true, protocols: ['sccache'] });
    const { token } = await api('admin/tokens', { subject: 'benchmark', caches: [project.cache], perms: ['sccache:read', 'sccache:write'] });
    let expected, expectedCode;
    const modes = [...Array(repeats).fill('uncached'), 'cold', ...Array(repeats).fill('warm')];
    for (const [index, mode] of modes.entries()) {
      const label = `${project.name}-${index}-${mode}`;
      console.log(`${new Date().toISOString()} START ${label}`);
      const local = join(work, 'local-' + label);
      await rm(local, { recursive: true, force: true });
      clientEnv = { ...baseEnv, SCCACHE_SERVER_UDS: join(work, 'server.sock'), SCCACHE_CONF: join(work, 'sccache.toml'),
        SCCACHE_DIR: local, SCCACHE_WEBDAV_ENDPOINT: new URL(`/_api/v1/sccache/default/${project.cache}/`, url).href,
        SCCACHE_WEBDAV_TOKEN: token, SCCACHE_WEBDAV_DISABLE_CREATE_DIR: 'true' };
      const cached = mode !== 'uncached';
      const env = cached ? { ...clientEnv, RUSTC_WRAPPER: sccache } : baseEnv;
      if (project.cache === 'rust') await rm(join(project.cwd, 'target'), { recursive: true, force: true });
      else await run('make', ['clean', 'DEBUG_LEVEL=0'], { ...project, log: label + '-clean.log' });
      if (cached) await run(sccache, ['--start-server'], { env: clientEnv });
      const logStart = server.getLogs().length;
      const start = performance.now();
      const command = project.cache === 'rust' ? 'cargo' : 'make';
      const args = project.cache === 'rust' ? ['build', '--release', '--locked', '--offline'] : [...makeArgs, `CC=${cached ? sccache + ' ' : ''}cc`, `CXX=${cached ? sccache + ' ' : ''}c++`];
      await run(command, args, { ...project, env, log: label + '.log' });
      // stop-server drains pending remote writes; include that cost in wall time.
      let stats = null;
      if (cached) {
        await run(sccache, ['--show-stats', '--stats-format', 'json'], { env: clientEnv }).then(text => writeFile(join(artifacts, label + '-stats.json'), text));
        stats = JSON.parse(await readFile(join(artifacts, label + '-stats.json'), 'utf8')).stats;
        await run(sccache, ['--stop-server'], { env: clientEnv, log: label + '-stop.log' });
      }
      const wallSeconds = (performance.now() - start) / 1000;
      const digest = await hash(join(project.cwd, project.output));
      // sccache coalesces empty C++ translation units, including their debug
      // metadata. Compare code to the uncached control; warm restores must
      // additionally match the entire cold-cache archive, including debug data.
      if (expected && (project.cache === 'rust' || mode !== 'cold')) assert.equal(digest, expected, `${label}: build output differs`);
      expected = digest;
      let codeDigest = digest;
      if (project.cache === 'cpp') {
        const stripped = join(work, 'code.a');
        await run('objcopy', ['--strip-debug', join(project.cwd, project.output), stripped]);
        codeDigest = await hash(stripped);
        await rm(stripped);
      }
      if (expectedCode) assert.equal(codeDigest, expectedCode, `${label}: compiled code differs`);
      expectedCode = codeDigest;
      if (project.cache === 'rust') {
        assert.equal(await run(join(project.cwd, project.output), ['--no-config', '-n', '^compiler-cache-hit$', join(work, 'search.txt')]), '2:compiler-cache-hit\n');
      } else {
        await run('c++', ['-std=c++17', '-I' + join(project.cwd, 'include'), join(work, 'smoke.cc'), join(project.cwd, project.output), '-pthread', '-ldl', '-lrt', '-o', join(work, 'smoke')]);
        await run(join(work, 'smoke'), [join(work, 'smoke-db')]);
        await rm(join(work, 'smoke-db'), { recursive: true, force: true });
      }
      const requests = server.getLogs().slice(logStart);
      await writeFile(join(artifacts, label + '-requests.json'), JSON.stringify(requests, null, 2));
      const sum = counts => Object.values(counts ?? {}).reduce((a, b) => a + b, 0);
      const result = { project: project.name, mode, index, wallSeconds, outputSha256: digest, codeSha256: codeDigest,
        hits: stats ? sum(stats.cache_hits?.counts) : null, misses: stats ? sum(stats.cache_misses?.counts) : null,
        writeErrors: stats?.cache_write_errors ?? null, readErrors: stats?.cache_read_errors ?? null,
        noncacheable: stats?.not_cached ?? null, storage: await api(`orgs/default/caches/${project.cache}/sccache`, undefined, 'GET'),
        artifacts: (await db.query('select count(*)::int as count, max(size)::bigint as largest_bytes, sum(size)::bigint as total_bytes from sccache_entries where uploaded_at is not null')).rows[0] };
      results.push(result);
      await writeFile(join(artifacts, 'results.json'), JSON.stringify(results, null, 2));
      console.log(JSON.stringify(result));
      if (cached) {
        assert.equal(result.writeErrors, 0, `${label}: cache write errors`);
        assert.equal(result.readErrors, 0, `${label}: cache read errors`);
        if (mode === 'warm') assert(result.hits > 0, `${label}: no remote hits`);
      }
      await rm(local, { recursive: true, force: true });
    }
  }
} finally {
  if (clientEnv) await run(sccache, ['--stop-server'], { env: clientEnv }).catch(() => {});
  await server?.close();
  await db?.end();
  await admin.query(`DROP DATABASE "${dbName}" WITH (FORCE)`);
  await admin.end();
}
