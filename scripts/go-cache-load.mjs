// Local-only real HTTP/workerd benchmark. No deployment or persistent storage.
// nix develop --command node scripts/go-cache-load.mjs > worker-before.jsonl 2> worker-before.log
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import http from 'node:http';
import { performance } from 'node:perf_hooks';

const require = createRequire(import.meta.url);
const wranglerRequire = createRequire(require.resolve('wrangler'));
const { Miniflare, Log, LogLevel, convertV4MiniflareOptions } = wranglerRequire('miniflare');
const { build } = wranglerRequire('esbuild');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const action = () => randomBytes(32).toString('hex');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const emit = value => process.stdout.write(`${JSON.stringify(value)}\n`);
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const source = process.env.GO_CACHE_WORKER_SOURCE ?? 'workers/go-cache/src/index.ts';
const bundled = await build({ entryPoints: [source], bundle: true, format: 'esm', write: false });
const mf = new Miniflare(convertV4MiniflareOptions({
  host: '127.0.0.1', port: 0,
  inspectorPort: process.env.GO_CACHE_INSPECT_HEAP === '1' ? 0 : undefined,
  workers: [{
    name: 'local-go-cache', script: bundled.outputFiles[0].text, modules: true, compatibilityDate: '2026-03-10',
    r2Buckets: ['ARTIFACTS'],
    bindings: { CACHE_NAMESPACE: 'local-load', RETENTION_SECONDS: '604800', READ_TOKEN: 'local-reader', WRITE_TOKEN: 'local-writer' },
  }],
  // Intentionally omit REQUEST_LIMIT: measure successful work, not 429s.
  log: new Log(LogLevel.WARN),
}));
const base = await mf.ready;
let inspector;
let heapReading;
let heapError;
let heapId = 0;
if (process.env.GO_CACHE_INSPECT_HEAP === '1') {
  const url = await mf.getInspectorURL();
  url.pathname = '/core:user:local-go-cache';
  inspector = new WebSocket(url);
  await new Promise((resolve, reject) => {
    inspector.addEventListener('open', resolve, { once: true });
    inspector.addEventListener('error', reject, { once: true });
  });
}
const processes = () => {
  const rows = [];
  for (const id of readdirSync('/proc').filter(id => /^\d+$/.test(id))) {
    try {
      const stat = readFileSync(`/proc/${id}/status`, 'utf8');
      const command = readFileSync(`/proc/${id}/cmdline`, 'utf8').replaceAll('\0', ' ');
      rows.push({ pid: Number(id), parent: Number(stat.match(/^PPid:\s+(\d+)/m)[1]), rssKiB: Number(stat.match(/^VmRSS:\s+(\d+)/m)?.[1] ?? 0), command });
    } catch { /* A process can exit while sampled. */ }
  }
  const children = new Set([process.pid]);
  for (let pass = 0; pass < 5; pass++) for (const row of rows) if (children.has(row.parent)) children.add(row.pid);
  return rows.filter(row => children.has(row.pid) && /\/workerd(?: |$)/.test(row.command));
};
let peak = 0;
const samples = [];
let phase = 'startup';
const sample = () => {
  const workers = processes();
  const rssKiB = workers.reduce((sum, row) => sum + row.rssKiB, 0);
  peak = Math.max(peak, rssKiB);
  const row = { elapsedMs: Math.round(performance.now()), phase, workerdRssKiB: rssKiB, nodeRssKiB: Math.round(process.memoryUsage().rss / 1024) };
  samples.push(row);
  if (inspector && !heapReading) {
    const id = ++heapId;
    heapReading = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Inspector heap sample timeout')), 5000);
      inspector.onmessage = event => {
        const message = JSON.parse(event.data);
        if (message.id !== id) return;
        clearTimeout(timeout);
        if (message.error) reject(new Error(JSON.stringify(message.error)));
        else resolve(message.result);
      };
      inspector.send(JSON.stringify({ id, method: 'Runtime.getHeapUsage' }));
    }).then(heap => { row.applicationHeapBytes = heap; }, error => { heapError = error; }).finally(() => { heapReading = undefined; });
  }
};
const timer = setInterval(sample, 100);
const statuses = {};
function request(path, { method = 'GET', body, output, token = 'local-reader', pauseMs = 0, cancel = false, expected, expectedDigest } = {}) {
  return new Promise((resolve, reject) => {
    const start = performance.now();
    const req = http.request(new URL(`/v1/actions/${path}`, base), {
      method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body ? { 'content-length': body.length, 'x-snowstead-output-id': output ?? digest(body) } : {}) },
    }, res => {
      const hash = createHash('sha256');
      let bytes = 0;
      statuses[res.statusCode] = (statuses[res.statusCode] ?? 0) + 1;
      if (cancel) {
        res.once('data', () => {
          res.destroy();
          if (res.statusCode !== 200) reject(new Error(`Cancelled GET expected 200, got ${res.statusCode}`));
          else resolve({ status: res.statusCode, bytes: 0, ms: performance.now() - start });
        });
        res.on('error', reject);
        res.resume();
        return;
      }
      if (pauseMs) { res.pause(); setTimeout(() => res.resume(), pauseMs); }
      res.on('data', chunk => { bytes += chunk.length; hash.update(chunk); });
      res.on('error', reject);
      res.on('end', () => {
        try {
          const actual = hash.digest('hex');
          if (expected !== undefined) assert(res.statusCode === expected, `${method}: expected ${expected}, got ${res.statusCode}`);
          if (expectedDigest) {
            assert(actual === expectedDigest, 'Downloaded body digest mismatch');
            assert(res.headers['x-snowstead-output-id'] === expectedDigest, 'Output header mismatch');
            assert(res.headers['cache-control'] === 'no-store', 'Private response cached publicly');
            assert(res.headers['cloudflare-cdn-cache-control'] === 'no-store', 'Outer CDN not disabled');
          }
          resolve({ status: res.statusCode, bytes, ms: performance.now() - start, source: res.headers['x-snowstead-cache'] });
        } catch (error) { reject(error); }
      });
    });
    req.setTimeout(60000, () => req.destroy(new Error('HTTP timeout')));
    req.on('error', reject);
    req.end(body);
  });
}
async function measured(name, count, concurrency, operation) {
  phase = name;
  sample();
  const baseline = samples.at(-1).workerdRssKiB;
  const offset = samples.length;
  const results = [];
  const errors = [];
  let next = 0;
  const start = performance.now();
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (next < count) {
      const index = next++;
      const started = performance.now();
      try { results.push({ ...await operation(index), ms: performance.now() - started }); } catch (error) { errors.push(String(error)); }
    }
  }));
  sample();
  const seconds = (performance.now() - start) / 1000;
  const latencies = results.map(result => result.ms).sort((a, b) => a - b);
  const bytes = results.reduce((sum, result) => sum + result.bytes, 0);
  const row = { name, count, concurrency, seconds, success: results.length, errors, operationsPerSecond: results.length / seconds, verifiedMiBPerSecond: bytes / 1048576 / seconds,
    p50Ms: latencies[Math.floor(latencies.length * 0.5)], p95Ms: latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * 0.95))],
    baselineWorkerdRssKiB: baseline, peakWorkerdRssKiB: Math.max(baseline, ...samples.slice(offset).map(s => s.workerdRssKiB)),
    hits: results.filter(result => result.source === 'HIT').length };
  emit(row);
  assert(errors.length === 0, `${name}: ${errors.join('; ')}`);
  return row;
}
try {
  emit({ runtime: 'local Miniflare/workerd, temporary Cache API + SQLite R2 emulator, real HTTP', source, heapInspector: Boolean(inspector), base: String(base), node: process.version, workers: processes(), rateLimit: 'omitted only in this local harness' });
  for (const size of [1024, 1048576, 16 * 1048576, 64 * 1048576]) {
    phase = `seed-${size}`;
    const body = Buffer.alloc(size, 0x61);
    const output = digest(body);
    const key = action();
    await request(key, { method: 'PUT', body, output, token: 'local-writer', expected: 201 });
    await measured(`cold-${size}`, 1, 1, () => request(key, { expected: 200, expectedDigest: output }));
    await sleep(300);
    for (let repeat = 1; repeat <= 3; repeat++) {
      await measured(`warm-${size}-r${repeat}`, size === 1024 ? 2400 : size === 1048576 ? 480 : 32, size <= 1048576 ? 12 : 4,
        () => request(key, { expected: 200, expectedDigest: output }));
    }
    await measured(`auth-denial-${size}`, 24, 8, i => request(key, { token: i % 2 ? '' : 'wrong-token', expected: i % 2 ? 401 : 403 }));
    if (size >= 16 * 1048576) {
      const keys = Array.from({ length: 4 }, action);
      for (const at of keys) await request(at, { method: 'PUT', body, output, token: 'local-writer', expected: 201 });
      await measured(`cold-slow-${size}`, 4, 4, i => request(keys[i], { pauseMs: 2000, expected: 200, expectedDigest: output }));
      const cancelled = Array.from({ length: 4 }, action);
      for (const at of cancelled) await request(at, { method: 'PUT', body, output, token: 'local-writer', expected: 201 });
      await measured(`cold-cancel-${size}`, 4, 4, i => request(cancelled[i], { cancel: true }));
      await sleep(500);
      await measured(`after-cancel-${size}`, 4, 4, i => request(cancelled[i], { expected: 200, expectedDigest: output }));
    }
  }
  const body = Buffer.alloc(1048576, 0x62);
  const output = digest(body);
  await measured('mixed-1MiB', 80, 8, async () => {
    const at = action();
    await request(at, { method: 'PUT', body, output, token: 'local-writer', expected: 201 });
    return request(at, { expected: 200, expectedDigest: output });
  });
  const small = Buffer.alloc(1024, 0x63);
  const other = Buffer.alloc(1024, 0x64);
  await measured('immutable-races', 20, 4, async () => {
    const at = action();
    const results = await Promise.all([small, small, other, other].map(body => request(at, { method: 'PUT', body, token: 'local-writer' })));
    assert(results.filter(r => r.status === 201).length === 1, 'Expected exactly one race winner');
    assert(results.filter(r => r.status === 204).length === 1, 'Expected one duplicate');
    assert(results.filter(r => r.status === 409).length === 2, 'Expected two conflicts');
    const winner = results.findIndex(r => r.status === 201);
    await request(at, { method: 'PUT', body: winner < 2 ? other : small, output: digest(winner < 2 ? small : other), token: 'local-writer', expected: 400 });
    return request(at, { expected: 200, expectedDigest: digest(winner < 2 ? small : other) });
  });
  const corrupt = action();
  await request(corrupt, { method: 'PUT', body: small, output: digest(other), token: 'local-writer', expected: 400 });
  await request(corrupt, { expected: 404 });
  await request(corrupt, { method: 'PUT', body: small, token: 'local-reader', expected: 403 });
  await request(corrupt, { expected: 404 });
  emit({ controls: 'corrupted fresh writes and read-only writes rejected without publication', passed: true });
  clearInterval(timer);
  await heapReading;
  if (heapError) throw heapError;
  emit({ complete: true, statuses, peakWorkerdRssKiB: peak, samples });
} finally {
  clearInterval(timer);
  inspector?.close();
  await mf.dispose();
}
