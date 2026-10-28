// Disposable stock-Zig/ZLS local HTTP/R2/Cache API gate. No cloud credentials.
// nix develop --command node scripts/zig-cache-benchmark.mjs
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, rm, cp, appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import assert from 'node:assert/strict';

const root = resolve(import.meta.dirname, '..');
const require = createRequire(import.meta.url);
const wrangler = createRequire(require.resolve('wrangler'));
const { Miniflare, convertV4MiniflareOptions } = wrangler('miniflare');
const { build } = wrangler('esbuild');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const scratch = await mkdtemp(join(tmpdir(), 'zig-snapshot-gate-'));
const evidence = resolve(process.env.ZIG_CACHE_PROOF_DIR ?? join(root, '.amp/in/artifacts/zig-snapshot'));
// Add the local exclude before producing evidence, preserving existing entries.
async function command(exe, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, args, { cwd: root, ...options });
    let stdout = '', stderr = '';
    child.stdout?.on('data', b => { stdout += b; });
    child.stderr?.on('data', b => { stderr += b; });
    child.on('error', reject);
    child.on('exit', code => code === 0 ? resolve({ stdout, stderr }) : reject(new Error(`${exe} exited ${code}\n${stderr}`)));
  });
}
const exclude = (await command('git', ['rev-parse', '--git-path', 'info/exclude'])).stdout.trim();
if (!(await readFile(exclude, 'utf8')).split('\n').includes('/.amp/in/')) await appendFile(exclude, '\n/.amp/in/\n');
await mkdir(evidence, { recursive: true });
let mf;
try {
  async function download(url, checksum, name) {
    const file = join(scratch, name);
    await command('curl', ['-fsSL', '--retry', '2', url, '-o', file]);
    assert.equal(hash(await readFile(file)), checksum, `checksum: ${url}`);
    return file;
  }
  const zigTar = await download('https://ziglang.org/download/0.17.0/zig-x86_64-linux-0.17.0.tar.xz', '1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026', 'zig.tar.xz');
  const zlsTar = await download('https://api.github.com/repos/zigtools/zls/tarball/0.17.0', '0eb143b5ab95f7d3db6b22898ba8782440debf15757f35838c96b9eb834e5a64', 'zls.tar.gz');
  await command('tar', ['-xJf', zigTar, '-C', scratch]);
  const toolchain = join(scratch, 'zig-x86_64-linux-0.17.0');
  const project = join(scratch, 'checkout');
  await mkdir(project);
  await command('tar', ['-xzf', zlsTar, '--strip-components=1', '-C', project]);
  const zig = join(toolchain, 'zig');
  // Resolve Zig's content-addressed dependencies before timing. In 0.17 these
  // live in zig-pkg inside the source tree, included in the client's input hash.
  await command(zig, ['build', '-h'], { cwd: project, env: { ...process.env, ZIG_GLOBAL_CACHE_DIR: join(scratch, 'prefetch-global') } });
  await rm(join(project, '.zig-cache'), { recursive: true, force: true });
  await rm(join(scratch, 'prefetch-global'), { recursive: true, force: true });
  const binary = join(scratch, 'snapshot-client');
  await command('go', ['build', '-o', binary, '.'], { cwd: join(root, 'apps/zig-cache') });
  const context = join(scratch, 'context');
  await writeFile(context, 'ZLS 542462c4ddf045493fa9ca028ee6bc3f38b2754a; vendored zig-pkg hashed; no external SDK; trusted Linux CI; release build\n');
  const bundled = await build({ entryPoints: [join(root, 'workers/zig-cache/src/index.ts')], bundle: true, format: 'esm', write: false });
  mf = new Miniflare(convertV4MiniflareOptions({ host: '127.0.0.1', port: 0, workers: [{
    name: 'zig-gate', script: bundled.outputFiles[0].text, modules: true, compatibilityDate: '2026-03-10',
    r2Buckets: ['ARTIFACTS'], bindings: { CACHE_NAMESPACE: 'disposable-zls', PUBLIC_READ: 'false', READ_TOKEN: 'local-reader', WRITE_TOKEN: 'local-writer' },
  }] }));
  const url = (await mf.ready).origin;
  const env = { ...process.env, SNOWSTEAD_ZIG_READ_TOKEN: 'local-reader', SNOWSTEAD_ZIG_WRITE_TOKEN: 'local-writer' };
  const rows = [];
  async function sample(name, { source = project, save = false, args = [], endpoint = url, controlled = true } = {}) {
    await rm(join(source, 'zig-out'), { recursive: true, force: true });
    const timeFile = join(evidence, `${name}.time`);
    const result = await command('time', ['-f', '%e %M', '-o', timeFile, binary, '-project', source, '-toolchain', toolchain, '-context', context, '-trust', 'zls-reviewed-v1', '-url', endpoint, '-scratch', join(scratch, controlled ? 'controlled-cache-session' : 'different-cache-session'), ...(save ? ['-save'] : []), '--', '-Doptimize=ReleaseFast', '--summary', 'all', ...args], { env });
    await writeFile(join(evidence, `${name}.log`), result.stderr + result.stdout);
    const [wallSeconds, buildPeakRssKiB] = (await readFile(timeFile, 'utf8')).trim().split(' ').map(Number);
    const output = await readFile(join(source, 'zig-out/bin/zls'));
    const version = await command(join(source, 'zig-out/bin/zls'), ['--version']);
    const row = { name, wallSeconds, buildPeakRssKiB,
      clientPeakRssKiB: Number(result.stderr.match(/client peak RSS KiB: (\d+)/)?.[1]),
      zigBuildSeconds: Number(result.stderr.match(/zig build seconds: ([\d.]+)/)?.[1]),
      restoredBytes: Number(result.stderr.match(/snapshot restored: (\d+)/)?.[1] ?? 0),
      savedBytes: Number(result.stderr.match(/snapshot saved: (\d+)/)?.[1] ?? 0),
      cachedSteps: (result.stderr.match(/cached/g) ?? []).length,
      outputSHA256: hash(output), version: version.stdout.trim(),
    };
    rows.push(row); console.log(JSON.stringify(row));
    await writeFile(join(evidence, 'results.json'), JSON.stringify(rows, null, 2));
    return row;
  }
  const cold = await sample('cold-save', { save: true });
  assert.ok(cold.savedBytes > 0);
  for (let i = 1; i <= 3; i++) {
    const warm = await sample(`empty-restore-${i}`, { save: i === 1 });
    assert.ok(warm.restoredBytes > 0); assert.equal(warm.outputSHA256, cold.outputSHA256);
    assert.equal(warm.savedBytes, 0, 'verified immutable hits must not be re-uploaded');
  }
  const refreshed = join(scratch, 'fresh-source');
  await cp(project, refreshed, { recursive: true });
  await rm(project, { recursive: true });
  await cp(refreshed, project, { recursive: true });
  await rm(refreshed, { recursive: true });
  const recheckout = await sample('fresh-checkout-same-path');
  assert.ok(recheckout.restoredBytes > 0); assert.equal(recheckout.outputSHA256, cold.outputSHA256);
  const occupied = join(scratch, 'occupied-session');
  await mkdir(occupied);
  await writeFile(join(occupied, 'marker'), 'do not delete');
  await assert.rejects(command(binary, ['-project', project, '-toolchain', toolchain, '-context', context, '-trust', 'zls-reviewed-v1', '-url', url, '-scratch', occupied], { env }), /file exists/);
  assert.equal(await readFile(join(occupied, 'marker'), 'utf8'), 'do not delete');
  const relocated = join(scratch, 'other-checkout');
  await cp(project, relocated, { recursive: true });
  assert.equal((await sample('relocated', { source: relocated })).restoredBytes, 0);
  assert.equal((await sample('different-cache-layout', { controlled: false })).restoredBytes, 0);
  const options = await sample('options', { args: ['-Dstrip=true'] });
  assert.equal(options.restoredBytes, 0); assert.notEqual(options.outputSHA256, cold.outputSHA256);
  assert.equal((await sample('target', { args: ['-Dtarget=x86_64-linux-musl', '-Dcpu=baseline'] })).restoredBytes, 0);
  const sourceFile = join(project, 'src/zls.zig');
  const before = await readFile(sourceFile);
  await appendFile(sourceFile, '\n// remote cache input mutation control\n');
  const changed = await sample('source-import-change');
  assert.equal(changed.restoredBytes, 0);
  await writeFile(sourceFile, before);
  await appendFile(context, 'external SDK identity changed\n');
  const external = await sample('external-context-change');
  assert.equal(external.restoredBytes, 0);
  const offline = await sample('offline', { endpoint: 'http://127.0.0.1:1' });
  assert.equal(offline.restoredBytes, 0); assert.equal(offline.savedBytes, 0);
  assert.equal(offline.cachedSteps, 0); assert.equal(offline.version, cold.version);
  // Two stock clean builds under the same selection key produced different
  // executable hashes in the initial gate (online 404 vs offline). Bitwise
  // reproducibility is not a stock-ZLS contract. Record it rather than hiding
  // the observation; warm restores above still require exact binary equality.
  await writeFile(join(evidence, 'clean-reproducibility.json'), JSON.stringify({
    onlineSHA256: external.outputSHA256, offlineSHA256: offline.outputSHA256,
    equal: external.outputSHA256 === offline.outputSHA256,
  }));
  // Real compiler failure from an embedFile mutation: never accept a stale
  // restored binary and never upload failed-build state, even with -save.
  await writeFile(join(project, 'src/snapshot-asset.txt'), 'good');
  await appendFile(sourceFile, '\ncomptime { if (@embedFile("snapshot-asset.txt")[0] != \'g\') @compileError("snapshot embed mutation detected"); }\n');
  assert.ok((await sample('embed-save', { save: true })).savedBytes > 0);
  await writeFile(join(project, 'src/snapshot-asset.txt'), 'bad!');
  await rm(join(project, 'zig-out'), { recursive: true, force: true });
  const bucket = await mf.getR2Bucket('ARTIFACTS');
  const beforeFailed = (await bucket.list()).objects.length;
  try {
    await command(binary, ['-project', project, '-toolchain', toolchain, '-context', context, '-trust', 'zls-reviewed-v1', '-url', url, '-scratch', join(scratch, 'controlled-cache-session'), '-save', '--', '-Doptimize=ReleaseFast', '--summary', 'all'], { env });
    assert.fail('embedFile mutation unexpectedly built');
  } catch (error) {
    assert.match(error.message, /snapshot embed mutation detected/);
    assert.match(error.message, /restore HTTP 404/);
    await writeFile(join(evidence, 'failed-embed-control.log'), error.message);
  }
  await assert.rejects(readFile(join(project, 'zig-out/bin/zls')), /ENOENT/);
  assert.equal((await bucket.list()).objects.length, beforeFailed);
  await writeFile(join(evidence, 'controls.json'), JSON.stringify({ occupiedScratchPreserved: true, embedFailureDetected: true, failedBuildUploadedObjects: 0 }));
} finally {
  await mf?.dispose();
  await rm(scratch, { recursive: true, force: true });
}
