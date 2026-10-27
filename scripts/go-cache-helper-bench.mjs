// Public GOCACHEPROG stress benchmark, with a real HTTP origin and helper process.
// Usage: node scripts/go-cache-helper-bench.mjs /absolute/path/to/helper
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createReadStream } from 'node:fs';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';

const binary = resolve(process.argv[2]);
const repeats = Number(process.env.BENCH_REPEATS ?? 3);
const count = Number(process.env.BENCH_REQUESTS ?? 32);
const sizes = (process.env.BENCH_MIB ?? '1,16').split(',').map(Number);
const root = await mkdtemp(join(tmpdir(), 'snowstead-helper-bench-'));
let body, output;
let uploads = 0;
const server = createServer(async (req, res) => {
  if (req.headers.authorization !== 'Bearer benchmark-token') {
    res.writeHead(403).end();
    return;
  }
  if (req.method === 'GET') {
    res.writeHead(200, { 'content-length': body.length, 'x-snowstead-output-id': output });
    res.end(body);
  } else {
    const hash = createHash('sha256');
    let size = 0;
    for await (const chunk of req) { hash.update(chunk); size += chunk.length; }
    assert.equal(size, body.length);
    assert.equal(hash.digest('hex'), output);
    assert.equal(req.headers['x-snowstead-output-id'], output);
    uploads++;
    res.writeHead(201).end();
  }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const results = [];
try {
  for (const mib of sizes) {
    body = Buffer.alloc(mib * 1024 * 1024, 0xa7);
    output = createHash('sha256').update(body).digest('hex');
    const encoded = body.toString('base64');
    for (const mode of ['get', 'put']) {
      for (let run = 0; run < repeats; run++) {
        const dir = join(root, `${mib}-${mode}-${run}`);
        uploads = 0;
        let peakKiB = 0;
        const start = performance.now();
        const child = spawn(binary, [], { env: {
          ...process.env, SNOWSTEAD_GO_CACHE_URL: `http://127.0.0.1:${server.address().port}`,
          SNOWSTEAD_GO_CACHE_TOKEN: 'benchmark-token', SNOWSTEAD_GO_CACHE_DIR: dir,
          SNOWSTEAD_GO_CACHE_READ_ONLY: 'false',
        }, stdio: ['pipe', 'pipe', 'pipe'] });
        const exited = once(child, 'exit');
        let sampling = false;
        const timer = setInterval(async () => {
          if (sampling) return;
          sampling = true;
          try {
            const status = await readFile(`/proc/${child.pid}/status`, 'utf8');
            peakKiB = Math.max(peakKiB, Number(status.match(/^VmHWM:\s+(\d+)/m)?.[1] ?? 0));
          } catch { /* process exited */ }
          sampling = false;
        }, 5);
        let stderr = '';
        child.stderr.on('data', chunk => { stderr += chunk; });
        const replies = new Map();
        const lines = createInterface({ input: child.stdout });
        const finished = (async () => {
          for await (const line of lines) {
            const reply = JSON.parse(line);
            assert(!replies.has(reply.ID), 'duplicate response');
            replies.set(reply.ID, reply);
          }
        })();
        const send = async value => {
          if (!child.stdin.write(value)) await once(child.stdin, 'drain');
        };
        for (let id = 1; id <= count; id++) {
          const action = createHash('sha256').update(`${id}`).digest('base64');
          const request = { ID: id, Command: mode, ActionID: action };
          if (mode === 'put') Object.assign(request, { OutputID: Buffer.from(output, 'hex').toString('base64'), BodySize: body.length });
          await send(JSON.stringify(request) + '\n');
          if (mode === 'put') { await send('"'); await send(encoded); await send('"\n'); }
        }
        child.stdin.end(JSON.stringify({ ID: count + 1, Command: 'close' }) + '\n');
        const [code, signal] = await exited;
        clearInterval(timer);
        await finished;
        const elapsedMs = performance.now() - start;
        assert.equal(code, 0, `${signal}: ${stderr}`);
        assert.equal(replies.size, count + 2);
        const paths = new Set();
        for (let id = 1; id <= count; id++) {
          const reply = replies.get(id);
          assert(!reply.Err && !reply.Miss, JSON.stringify(reply));
          assert.equal((await stat(reply.DiskPath)).size, body.length);
          paths.add(reply.DiskPath);
          if (mode === 'get') assert.equal(Buffer.from(reply.OutputID, 'base64').toString('hex'), output);
        }
        for (const path of paths) {
          const hash = createHash('sha256');
          for await (const chunk of createReadStream(path)) hash.update(chunk);
          assert.equal(hash.digest('hex'), output);
        }
        assert.match(stderr, /upload_errors=0 conflicts=0/);
        if (mode === 'put') assert.equal(uploads, count);
        else assert.match(stderr, new RegExp(`remote_hits=${count} `));
        const result = { mode, mib, requests: count, run, elapsed_ms: Math.round(elapsedMs), peak_helper_rss_kib: peakKiB,
          throughput_mib_s: Math.round(count * mib / (elapsedMs / 1000)), summary: stderr.trim() };
        results.push(result);
        console.log(JSON.stringify(result));
        await rm(dir, { recursive: true, force: true });
      }
    }
  }
  for (const mib of sizes) for (const mode of ['get', 'put']) {
    const selected = results.filter(result => result.mib === mib && result.mode === mode);
    const median = key => selected.map(result => result[key]).sort((a, b) => a - b)[Math.floor(selected.length / 2)];
    console.log(JSON.stringify({ median: true, mode, mib, elapsed_ms: median('elapsed_ms'), peak_helper_rss_kib: median('peak_helper_rss_kib'), throughput_mib_s: median('throughput_mib_s') }));
  }
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  await rm(root, { recursive: true, force: true });
}
