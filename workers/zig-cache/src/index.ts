/** Isolated snapshot spike. No hosted Go/Nix permissions or buckets. */
interface Env {
  ARTIFACTS: R2Bucket;
  CACHE_NAMESPACE: string;
  READ_TOKEN: string;
  WRITE_TOKEN: string;
  PUBLIC_READ: string;
}
const MAX_BYTES = 96 * 1024 * 1024;
const RETENTION = 604800;
const HEADER = 'x-snapshot-sha256';
const encoder = new TextEncoder();

function reply(status: number, body?: string): Response {
  return new Response(body ?? null, { status, headers: {
    'cache-control': 'no-store', 'cloudflare-cdn-cache-control': 'no-store',
  } });
}

async function matches(value: string, expected: string): Promise<boolean> {
  const hashes = await Promise.all([value, expected].map(v => crypto.subtle.digest('SHA-256', encoder.encode(v))));
  const a = new Uint8Array(hashes[0]);
  const b = new Uint8Array(hashes[1]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function returned(response: Response, hit: boolean, head: boolean): Response {
  const headers = new Headers(response.headers);
  headers.set('cache-control', 'no-store');
  headers.set('cloudflare-cdn-cache-control', 'no-store');
  headers.set('x-snowstead-cache', hit ? 'HIT' : 'MISS');
  return new Response(head ? null : response.body, { headers });
}

export default {
  async fetch(request: Request, env): Promise<Response> {
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(env.CACHE_NAMESPACE) || !env.WRITE_TOKEN || !env.READ_TOKEN || env.WRITE_TOKEN === env.READ_TOKEN || !['true', 'false'].includes(env.PUBLIC_READ)) return reply(503);
    const url = new URL(request.url);
    const route = /^\/v1\/snapshots\/([a-f0-9]{64})$/.exec(url.pathname);
    if (!route) return reply(404);
    if (!['GET', 'HEAD', 'PUT'].includes(request.method)) return reply(405);
    const auth = request.headers.get('authorization') ?? '';
    if (auth.length > 4096) return reply(403);
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const writer = token !== '' && await matches(token, env.WRITE_TOKEN);
    if (request.method === 'PUT' ? !writer : env.PUBLIC_READ !== 'true' && !writer && !(token !== '' && await matches(token, env.READ_TOKEN))) return reply(403);
    // Even private warm-cache reads are authorized before lookup. Visibility is
    // part of the key, so changing to private cannot expose a public warm entry.
    const key = `zig/${env.CACHE_NAMESPACE}/snapshots/${route[1]}`;
    const cacheKey = new Request(`${url.origin}/_zig_snapshot/${env.PUBLIC_READ}/${key}`);
    if (request.method === 'PUT') {
      const sha256 = request.headers.get(HEADER) ?? '';
      const rawLength = request.headers.get('content-length') ?? '';
      if (!/^[a-f0-9]{64}$/.test(sha256) || !/^\d+$/.test(rawLength)) return reply(400);
      const size = Number(rawLength);
      if (!Number.isSafeInteger(size) || size < 1 || size > MAX_BYTES) return reply(413);
      if (!request.body) return reply(400);
      try {
        const object = await env.ARTIFACTS.put(key, request.body.pipeThrough(new FixedLengthStream(size)), {
          sha256, onlyIf: { etagDoesNotMatch: '*' }, customMetadata: { sha256 },
        });
        if (object) return reply(201);
        const existing = await env.ARTIFACTS.head(key);
        return reply(existing?.customMetadata?.sha256 === sha256 ? 204 : 409);
      } catch (error) {
        if (error instanceof Error && /checksum|content length|FixedLengthStream|client disconnected/i.test(error.message)) return reply(400);
        throw error;
      }
    }
    const head = request.method === 'HEAD';
    let cached: Response | undefined;
    try { cached = await caches.default.match(cacheKey); }
    catch { /* Cache API is optional; continue to R2. */ }
    if (cached) {
      if (head) await cached.body?.cancel();
      return returned(cached, true, head);
    }
    const object = await env.ARTIFACTS.get(key);
    if (!object) return reply(404);
    const remaining = object.uploaded.getTime() + RETENTION * 1000 - Date.now();
    if (remaining <= 0) { await object.body.cancel(); return reply(404); }
    const response = new Response(object.body, { headers: {
      'content-type': 'application/gzip', 'content-length': String(object.size),
      [HEADER]: object.customMetadata?.sha256 ?? '',
      'cache-control': `public, max-age=${Math.min(3600, Math.floor(remaining / 1000))}`,
    } });
    if (head) { await object.body.cancel(); return returned(response, false, true); }
    // No response.clone()/tee: a slow reader must not buffer a complete snapshot
    // in isolate memory. Populate sequentially, then stream a new read.
    try {
      await caches.default.put(cacheKey, response);
      const filled = await caches.default.match(cacheKey);
      if (filled) return returned(filled, false, false);
    } catch { /* Cache API is optional; R2 remains the source of truth. */ }
    const retry = await env.ARTIFACTS.get(key);
    if (!retry) return reply(404);
    return returned(new Response(retry.body, { headers: response.headers }), false, false);
  },
} satisfies ExportedHandler<Env>;
