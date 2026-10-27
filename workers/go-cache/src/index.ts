/** A deployment is a single trusted build cache, independent of Nix. */
interface Env {
  ARTIFACTS: R2Bucket;
  CACHE_NAMESPACE: string;
  RETENTION_SECONDS: string;
  READ_TOKEN: string;
  WRITE_TOKEN: string;
  REQUEST_LIMIT?: RateLimit;
}

const MAX_BYTES = 64 * 1024 * 1024;
const OUTPUT_HEADER = 'x-snowstead-output-id';
const encoder = new TextEncoder();

function reply(status: number, message = ''): Response {
  return new Response(message || null, {
    status,
    headers: { 'cache-control': 'no-store', 'cloudflare-cdn-cache-control': 'no-store' },
  });
}

async function matches(value: string, expected: string): Promise<boolean> {
  const [a, b] = await Promise.all([value, expected].map(value => crypto.subtle.digest('SHA-256', encoder.encode(value))));
  const left = new Uint8Array(a);
  const right = new Uint8Array(b);
  let different = 0;
  for (let i = 0; i < left.length; i++) different |= left[i] ^ right[i];
  return different === 0;
}

function returned(response: Response, source: string, head: boolean): Response {
  const headers = new Headers(response.headers);
  // Only the explicitly managed, authenticated internal cache may retain bytes.
  headers.set('cache-control', 'no-store');
  headers.set('cloudflare-cdn-cache-control', 'no-store');
  headers.set('x-snowstead-cache', source);
  return new Response(head ? null : response.body, { status: response.status, headers });
}

export default {
  async fetch(request: Request, env, ctx): Promise<Response> {
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(env.CACHE_NAMESPACE)
      || !env.READ_TOKEN || !env.WRITE_TOKEN || env.READ_TOKEN === env.WRITE_TOKEN) {
      return reply(503, 'Cache credentials or namespace are not configured');
    }
    const retention = Number(env.RETENTION_SECONDS);
    if (!Number.isSafeInteger(retention) || retention < 1 || retention > 604800) {
      return reply(503, 'Retention must be between 1 and 604800 seconds');
    }
    const url = new URL(request.url);
    const route = /^\/v1\/actions\/([a-f0-9]{64})$/.exec(url.pathname);
    if (!route) return reply(404);
    if (!['GET', 'HEAD', 'PUT'].includes(request.method)) {
      const response = reply(405);
      response.headers.set('allow', 'GET, HEAD, PUT');
      return response;
    }

    const authorization = request.headers.get('authorization') ?? '';
    if (!authorization.startsWith('Bearer ') || authorization.length > 4096) return reply(401);
    const token = authorization.slice(7);
    const writer = await matches(token, env.WRITE_TOKEN);
    if (!writer && (request.method === 'PUT' || !(await matches(token, env.READ_TOKEN)))) return reply(403);
    if (env.REQUEST_LIMIT && !(await env.REQUEST_LIMIT.limit({ key: writer ? 'writer' : 'reader' })).success) {
      return reply(429, 'Rate limit exceeded');
    }

    // Authorization runs even on warm CDN hits. Never share namespaces, never
    // put private compiler outputs into the public Nix bucket, and ignore query
    // strings and caller-controlled conditional headers when selecting objects.
    const key = `go/${env.CACHE_NAMESPACE}/actions/${route[1]}`;
    const cacheKey = new Request(`${url.origin}/_snowstead_go_cdn/${retention}/${key}`);
    if (request.method === 'PUT') {
      const output = request.headers.get(OUTPUT_HEADER) ?? '';
      const length = request.headers.get('content-length') ?? '';
      if (!/^[a-f0-9]{64}$/.test(output) || !/^\d+$/.test(length)) return reply(400, 'Output ID and content length are required');
      const size = Number(length);
      if (!Number.isSafeInteger(size) || size > MAX_BYTES) return reply(413);
      if (size > 0 && request.body === null) return reply(400, 'Artifact body is required');
      // R2 requires a known-length stream. FixedLengthStream also rejects
      // truncated or oversized bodies without buffering an artifact in memory.
      const body = request.body?.pipeThrough(new FixedLengthStream(size)) ?? new Uint8Array();
      let object: R2Object | null;
      try {
        object = await env.ARTIFACTS.put(key, body, {
          // R2 verifies the actual bytes, not just uploader-provided metadata.
          sha256: output,
          onlyIf: { etagDoesNotMatch: '*' },
          customMetadata: { output },
          httpMetadata: { contentType: 'application/octet-stream' },
        });
      } catch (error) {
        // Stream length failures can arrive before R2's checksum validation.
        if (error instanceof Error && /checksum|content length|FixedLengthStream|client disconnected/i.test(error.message)) {
          return reply(400, 'Artifact checksum or length mismatch');
        }
        throw error;
      }
      if (object) return reply(201);
      const existing = await env.ARTIFACTS.head(key);
      // Go's action ID is not a body hash. A different valid output for the
      // same action is a conflict, never a last-writer-wins update.
      return reply(existing?.customMetadata?.output === output ? 204 : 409);
    }

    const head = request.method === 'HEAD';
    const cached = await caches.default.match(cacheKey);
    if (cached) {
      if (head) await cached.body?.cancel();
      return returned(cached, 'HIT', head);
    }
    let object: R2Object | null;
    let body: ReadableStream | null = null;
    if (head) {
      object = await env.ARTIFACTS.head(key);
    } else {
      const result = await env.ARTIFACTS.get(key);
      object = result;
      body = result?.body ?? null;
    }
    if (!object) return reply(404);
    const remaining = object.uploaded.getTime() + retention * 1000 - Date.now();
    if (remaining <= 0) {
      await body?.cancel();
      return reply(404);
    }
    const ttl = Math.min(3600, Math.floor(remaining / 1000));
    const response = new Response(body, {
      headers: {
        'content-type': 'application/octet-stream',
        'content-length': String(object.size),
        [OUTPUT_HEADER]: object.customMetadata?.output ?? '',
        'cache-control': `public, max-age=${ttl}`,
        etag: object.httpEtag,
      },
    });
    if (!head && ttl > 0) ctx.waitUntil(caches.default.put(cacheKey, response.clone()));
    return returned(response, 'MISS', head);
  },
} satisfies ExportedHandler<Env>;
