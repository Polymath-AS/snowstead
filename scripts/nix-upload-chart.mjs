// Dependency-free report: node scripts/nix-upload-chart.mjs runs.jsonl chart.svg [push|requests|reads]
// Also writes chart.summary.json. Percentiles use nearest rank: sorted[ceil(p * n) - 1].
// Variant colors follow first appearance: append experiments to preserve existing assignments.
import { readFile, writeFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { parseArgs } from 'node:util';

const escape = (value) => String(value).replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;',
})[char]);
const failedStatus = (status) => status < 200 || status >= 400;
const presentError = (value) => value !== undefined && value !== null && value !== false && value !== '';
const finiteLatency = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const percentile = (sorted, p) => sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)];
const fmt = (value) => new Intl.NumberFormat('en-US', { maximumFractionDigits: 3 }).format(value);
const readPhases = new Set(['cold-narinfo', 'warm-narinfo', 'nar-download']);

function validate(row, line) {
  const fail = (message) => { throw new Error(`Line ${line}: ${message}`); };
  if (!row || typeof row !== 'object' || Array.isArray(row)) fail('expected an object');
  for (const key of ['variant', 'workload']) {
    if (typeof row[key] !== 'string' || !row[key].trim()) fail(`${key} must be a nonempty string`);
    if (/[\x00-\x1f\x7f]/.test(row[key])) fail(`${key} must not contain control characters`);
  }
  if (!Number.isInteger(row.round) || (row.round < 0 && row.warmup !== true)) fail('measured round must be a nonnegative integer');
  if (typeof row.warmup !== 'boolean') fail('warmup must be boolean');
  if (!finiteLatency(row.seconds) || !Number.isFinite(row.seconds * 1000)) fail('seconds must be finite and nonnegative');
  for (const kind of ['requests', 'reads']) {
    if (kind === 'reads' && row.reads === undefined) continue;
    if (!Array.isArray(row[kind])) fail(`${kind} must be an array`);
    for (const [index, sample] of row[kind].entries()) {
      if (!sample || typeof sample.phase !== 'string' || !sample.phase.trim()
        || /[\x00-\x1f\x7f]/.test(sample.phase)) fail(`${kind}[${index}] needs a phase`);
      if (kind === 'reads' && !readPhases.has(sample.phase)) fail(`unknown read phase ${sample.phase}`);
      if (!finiteLatency(sample.ms)) fail(`${kind}[${index}].ms must be finite and nonnegative`);
      if (!Number.isInteger(sample.status) || sample.status < 0 || sample.status > 599) {
        fail(`${kind}[${index}].status must be an integer from 0 to 599 (0 = transport failure)`);
      }
      if (sample.timings !== undefined) {
        if (!sample.timings || typeof sample.timings !== 'object' || Array.isArray(sample.timings)) fail('timings must be a phase map');
        for (const [phase, ms] of Object.entries(sample.timings)) {
          if (!/^[a-z_]+$/.test(phase) || !finiteLatency(ms)) fail('invalid server timing');
        }
      }
    }
  }
}

function summarize(samples) {
  const sorted = samples.map((sample) => sample.ms).sort((a, b) => a - b);
  const statuses = {};
  for (const sample of samples) {
    if (sample.status !== undefined) statuses[sample.status] = (statuses[sample.status] ?? 0) + 1;
  }
  return {
    count: sorted.length, errors: samples.filter((sample) => sample.error).length,
    runCount: new Set(samples.map((sample) => sample.line)).size,
    min: sorted[0], q1: percentile(sorted, 0.25), median: percentile(sorted, 0.5),
    q3: percentile(sorted, 0.75), p95: percentile(sorted, 0.95),
    p99: percentile(sorted, 0.99), max: sorted.at(-1),
    p99ReliableSampleSize: sorted.length >= 100, statuses,
  };
}

function render(groups, variants, colors, warmups) {
  const width = 1440;
  const parts = [];
  let y = 0;
  const text = (x, top, value, size = 14, extra = '') => parts.push(
    `<text x="${x}" y="${top}" font-size="${size}" ${extra}>${escape(value)}</text>`,
  );
  const line = (x1, y1, x2, y2, extra = '') => parts.push(
    `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" ${extra}/>`,
  );
  const dash = (variant) => {
    const index = variants.indexOf(variant);
    return index ? ` stroke-dasharray="${3 + index * 2} 3"` : '';
  };
  const point = (x, top, color, error, title) => {
    // Failure crosses and success circles remain distinguishable without color.
    parts.push(`<g stroke="${color}" fill="${color}"><title>${escape(title)}</title>`);
    if (error) {
      line(x - 4, top - 4, x + 4, top + 4, 'stroke-width="2"');
      line(x - 4, top + 4, x + 4, top - 4, 'stroke-width="2"');
    } else {
      parts.push(`<circle cx="${x}" cy="${top}" r="2.8" fill-opacity="0.65"/>`);
    }
    parts.push('</g>');
  };
  text(36, 40, 'Nix upload experiments — full latency distributions', 26, 'font-weight="700"');
  text(36, 70, `Latency in milliseconds, not throughput. ${warmups} warmup runs excluded; no outlier or error samples removed.`);
  text(36, 94, 'Boxes: nearest-rank Q1 / median / Q3; whiskers: min / max. Every observation is plotted. × = error; ● = success.');
  text(36, 118, 'ECDF: exact right-continuous steps including ties and failures. Hover points for raw values, round, and status.');
  text(36, 142, 'Percentiles: sorted[ceil(p × n) − 1]. p99 is not reliable below 100 samples; request samples within runs are correlated.');
  text(36, 166, 'Error: HTTP status outside 200–399 (including transport status 0), or explicit run error / ok:false / success:false.');
  text(36, 190, 'Server subphases overlap their parent and concurrent lanes; do not add them. Local Worker timers have millisecond granularity.');
  y = 222;
  for (const variant of variants) {
    line(36, y - 5, 96, y - 5, `stroke="${colors[variant]}" stroke-width="3"${dash(variant)}`);
    text(108, y, variant, 14, 'font-weight="600"');
    y += 24;
  }
  y += 16;
  for (const group of groups) {
    const height = 345 + group.series.length * 76;
    parts.push(`<rect x="20" y="${y}" width="1400" height="${height - 16}" rx="8" fill="#fff" stroke="#cbd5e1"/>`);
    text(40, y + 30, `${group.workload} · ${group.kind === 'push' ? 'End-to-end push' : group.kind === 'requests' ? 'Request phase' : 'Read phase'}${group.phase ? ` · ${group.phase}` : ''}`, 20, 'font-weight="700"');
    text(40, y + 54, 'Individual samples and min/max box plot (linear latency axis)', 13);
    const max = Math.max(...group.series.map((series) => series.stats.max)) || 1;
    const left = 360;
    const right = 1370;
    const scale = (ms) => left + (ms / max) * (right - left);
    const first = y + 90;
    for (const [index, series] of group.series.entries()) {
      const top = first + index * 76;
      const { stats, variant, samples } = series;
      const color = colors[variant];
      text(40, top - 6, variant, 14, 'font-weight="600"');
      text(40, top + 14, `n=${stats.count}; runs=${stats.runCount}; errors=${stats.errors}`, 12);
      line(scale(stats.min), top, scale(stats.max), top, `stroke="${color}" stroke-width="2"`);
      for (const value of [stats.min, stats.max]) line(scale(value), top - 8, scale(value), top + 8, `stroke="${color}"`);
      parts.push(`<rect x="${scale(stats.q1)}" y="${top - 10}" width="${Math.max(1, scale(stats.q3) - scale(stats.q1))}" height="20" fill="${color}" fill-opacity="0.14" stroke="${color}"/>`);
      line(scale(stats.median), top - 12, scale(stats.median), top + 12, `stroke="${color}" stroke-width="2"`);
      samples.forEach((sample, sampleIndex) => point(scale(sample.ms), top + ((sampleIndex * 17) % 29) - 14, color, sample.error,
        `${variant}; ${sample.ms} ms; round ${sample.round}; line ${sample.line}; ${sample.status === undefined ? 'run' : `status ${sample.status}`}; ${sample.error ? 'ERROR' : 'success'}`));
      text(left, top + 35, `median ${fmt(stats.median)} · p95 ${fmt(stats.p95)} · p99 ${fmt(stats.p99)}${stats.count < 100 ? ' (n<100)' : ''} · max ${fmt(stats.max)} ms`, 12);
    }
    const axis = first + group.series.length * 76 - 24;
    const ticks = (top) => {
      line(left, top, right, top, 'stroke="#64748b"');
      for (let i = 0; i <= 5; i++) {
        const x = left + (i / 5) * (right - left);
        line(x, top, x, top + 4, 'stroke="#64748b"');
        text(x, top + 20, fmt((i / 5) * max), 11, 'text-anchor="middle"');
      }
      text(right, top + 37, 'Latency (ms)', 12, 'text-anchor="end"');
    };
    ticks(axis);
    const ecdfTop = axis + 72;
    const ecdfBottom = ecdfTop + 140;
    text(40, ecdfTop, 'Full empirical CDF', 16, 'font-weight="600"');
    text(40, ecdfTop + 22, 'Fraction of all samples ≤ latency', 12);
    for (const fraction of [0, 0.5, 1]) {
      const top = ecdfBottom - fraction * 140;
      line(left, top, right, top, 'stroke="#e2e8f0"');
      text(left - 12, top + 4, `${fraction * 100}%`, 11, 'text-anchor="end"');
    }
    for (const series of group.series) {
      const sorted = [...series.samples].sort((a, b) => a.ms - b.ms);
      let path = `M ${left} ${ecdfBottom}`;
      for (const [i, sample] of sorted.entries()) path += ` H ${scale(sample.ms)} V ${ecdfBottom - ((i + 1) / sorted.length) * 140}`;
      path += ` H ${right}`;
      parts.push(`<path d="${path}" fill="none" stroke="${colors[series.variant]}" stroke-width="2"${dash(series.variant)}><title>${escape(series.variant)}</title></path>`);
      // Every ECDF observation has its own point as well, including tied observations.
      sorted.forEach((sample, i) => point(scale(sample.ms), ecdfBottom - ((i + 1) / sorted.length) * 140,
        colors[series.variant], sample.error, `${series.variant}: ${sample.ms} ms; ECDF ${(i + 1)}/${sorted.length}`));
    }
    ticks(ecdfBottom);
    y += height;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${y + 16}" viewBox="0 0 ${width} ${y + 16}" role="img" aria-labelledby="title desc"><title id="title">Nix upload latency distributions</title><desc id="desc">All non-warmup observations, errors, min/max box plots, and full empirical cumulative distributions, separated by workload and phase. Exact statistics are in the companion summary JSON.</desc><rect width="100%" height="100%" fill="#f8fafc"/><g font-family="system-ui, sans-serif" fill="#172033">${parts.join('\n')}</g></svg>\n`;
}

async function main() {
  const { positionals: [input, output, kind, ...extra], values } = parseArgs({
    allowPositionals: true, options: { colors: { type: 'string' } },
  });
  if (!input || !output || extra.length || (kind && !['push', 'requests', 'reads'].includes(kind))) {
    throw new Error('Usage: node scripts/nix-upload-chart.mjs runs.jsonl chart.svg [push|requests|reads] [--colors previous.summary.json]');
  }
  if (extname(output).toLowerCase() !== '.svg') throw new Error('Output path must end in .svg');
  const summaryPath = output.slice(0, -4) + '.summary.json';
  if ([output, summaryPath].some((path) => resolve(path) === resolve(input))) throw new Error('Output must not overwrite input');
  const rows = [];
  for (const [index, source] of (await readFile(input, 'utf8')).split(/\r?\n/).entries()) {
    if (!source.trim()) continue;
    let row;
    try { row = JSON.parse(source); } catch { throw new Error(`Line ${index + 1}: invalid JSON`); }
    validate(row, index + 1);
    rows.push({ ...row, line: index + 1 });
  }
  const measured = rows.filter((row) => !row.warmup);
  if (!measured.length) throw new Error('No measured samples: input is empty or contains only warmups');
  const variants = [...new Set(measured.map((row) => row.variant))];
  // Colorblind-friendly qualitative palette, then non-repeating golden-angle hues.
  // Identity is also encoded by labels, row position, and ECDF dash patterns.
  const palette = ['#0072b2', '#d55e00', '#009e73', '#cc79a7', '#332288', '#882255', '#aa6600', '#117788'];
  const colors = values.colors ? JSON.parse(await readFile(values.colors, 'utf8')).colors : {};
  if (!colors || typeof colors !== 'object' || Array.isArray(colors)
    || Object.values(colors).some(color => typeof color !== 'string' || !/^(#[0-9a-f]{6}|hsl\([\d.]+ 65% 34%\))$/i.test(color))) {
    throw new Error('Invalid previous color map');
  }
  for (const variant of variants) if (!Object.hasOwn(colors, variant)) {
    const index = Object.keys(colors).length;
    colors[variant] = palette[index] ?? `hsl(${((index * 137.507764) % 360).toFixed(6)} 65% 34%)`;
  }
  const panels = new Map();
  const add = (row, kind, phase, sample) => {
    const key = JSON.stringify([row.workload, kind, phase]);
    if (!panels.has(key)) panels.set(key, { workload: row.workload, kind, phase, variants: new Map() });
    const panel = panels.get(key);
    if (!panel.variants.has(row.variant)) panel.variants.set(row.variant, []);
    panel.variants.get(row.variant).push({ ...sample, round: row.round, line: row.line });
  };
  for (const row of measured) {
    const requestError = row.requests.some((sample) => failedStatus(sample.status));
    const readError = (row.reads ?? []).some((sample) => failedStatus(sample.status));
    const error = presentError(row.error) || (Array.isArray(row.errors) && row.errors.length > 0) || row.ok === false || row.success === false
      || (typeof row.status === 'number' && failedStatus(row.status)) || requestError || readError;
    add(row, 'push', '', { ms: row.seconds * 1000, error });
    for (const kind of ['requests', 'reads']) {
      for (const sample of row[kind] ?? []) {
        add(row, kind, sample.phase, { ms: sample.ms, status: sample.status, error: failedStatus(sample.status) });
        for (const [phase, ms] of Object.entries(sample.timings ?? {})) {
          add(row, kind, `${sample.phase}/${phase}`, { ms, status: sample.status, error: failedStatus(sample.status) });
        }
      }
    }
  }
  const kindOrder = { push: 0, requests: 1, reads: 2 };
  const groups = [...panels.values()].filter(panel => !kind || panel.kind === kind).sort((a, b) => a.workload.localeCompare(b.workload)
    || kindOrder[a.kind] - kindOrder[b.kind] || a.phase.localeCompare(b.phase)).map((panel) => ({
    workload: panel.workload, kind: panel.kind, phase: panel.phase, unit: 'ms',
    series: [...panel.variants].sort(([a], [b]) => a.localeCompare(b)).map(([variant, samples]) => ({
      variant, color: colors[variant], stats: summarize(samples), samples,
    })),
  }));
  const warmups = rows.length - measured.length;
  const summary = {
    schemaVersion: 1, inputRows: rows.length, measuredRuns: measured.length, excludedWarmupRuns: warmups,
    percentileMethod: 'nearest rank: sorted[ceil(p * n) - 1]', unit: 'ms',
    colorAssignment: 'Previous summary colors, then first appearance of new measured variants. Labels and dash patterns supplement colors.',
    errorDefinition: 'Run error/ok:false/success:false/status outside 200–399, or any failed request/read. Phase error: status outside 200–399; 0 means transport failure.',
    caveats: ['p99 is not reliable below 100 samples.', 'Request and read samples within a run are correlated.', 'All measured errors and outliers are included; latency is not throughput.'],
    colors, groups,
  };
  await writeFile(output, render(groups, variants, colors, warmups));
  await writeFile(summaryPath, JSON.stringify(summary, null, 2) + '\n');
  console.log(`Wrote ${output} and ${summaryPath}: ${measured.length} measured runs, ${warmups} warmups excluded, ${groups.length} metric panels.`);
}

main().catch((error) => { console.error(`nix-upload-chart: ${error.message}`); process.exitCode = 1; });
