import { env, SELF, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import worker from '../src/index.js';

const writer = 'test-writer-secret';
const reader = 'test-reader-secret';
const data = new TextEncoder().encode('a real compiled output, not its cache key');

async function hash(bytes: Uint8Array): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function path(): Promise<string> {
  return `/v1/actions/${await hash(crypto.getRandomValues(new Uint8Array(32)))}`;
}

async function put(at: string, bytes = data, token = writer, output?: string): Promise<Response> {
  return SELF.fetch(`https://cache.test${at}`, {
    method: 'PUT',
    headers: { authorization: `Bearer ${token}`, 'content-length': String(bytes.length), 'x-snowstead-output-id': output ?? await hash(bytes) },
    body: bytes,
  });
}

function get(at: string, token = reader): Promise<Response> {
  return SELF.fetch(`https://cache.test${at}`, { headers: { authorization: `Bearer ${token}` } });
}

describe('private Go artifact cache', () => {
  it('stores verified artifacts and serves a warm CDN hit only after authorization', async () => {
    const at = await path();
    expect((await put(at)).status).toBe(201);
    const config = { ...env, READ_TOKEN: reader, WRITE_TOKEN: writer };
    const ctx = createExecutionContext();
    const first = await worker.fetch(new Request(`https://cache.test${at}`, { headers: { authorization: `Bearer ${reader}` } }), config, ctx);
    expect(first.headers.get('x-snowstead-cache')).toBe('MISS');
    expect(new Uint8Array(await first.arrayBuffer())).toEqual(data);
    await waitOnExecutionContext(ctx);

    const second = await get(`${at}?ignored=1`);
    expect(second.headers.get('x-snowstead-cache')).toBe('HIT');
    expect(second.headers.get('cache-control')).toBe('no-store');
    expect(second.headers.get('cloudflare-cdn-cache-control')).toBe('no-store');
    expect(second.headers.get('x-snowstead-output-id')).toBe(await hash(data));
    expect(new Uint8Array(await second.arrayBuffer())).toEqual(data);
    expect((await get(at, 'not-a-token')).status).toBe(403);
    expect((await SELF.fetch(`https://cache.test${at}`)).status).toBe(401);
    // Rotation is effective even while the old artifact is cached.
    const rotated = { ...config, READ_TOKEN: 'new-reader-secret', WRITE_TOKEN: 'new-writer-secret' };
    const rotation = createExecutionContext();
    expect((await worker.fetch(new Request(`https://cache.test${at}`, { headers: { authorization: `Bearer ${reader}` } }), rotated, rotation)).status).toBe(403);
    await waitOnExecutionContext(rotation);
  });

  it('rejects reader writes and invalid checksums without publishing bytes', async () => {
    const at = await path();
    expect((await put(at, data, reader)).status).toBe(403);
    expect((await put(at, data, writer, '0'.repeat(64))).status).toBe(400);
    expect((await get(at)).status).toBe(404);
    expect((await put(at)).status).toBe(201);
    expect((await put(at)).status).toBe(204);
  });

  it('rejects declared body lengths that do not match the stream without publishing an action', async () => {
    for (const length of [data.length - 1, data.length + 1]) {
      const at = await path();
      const ctx = createExecutionContext();
      const response = await worker.fetch(new Request(`https://cache.test${at}`, {
        method: 'PUT',
        headers: { authorization: `Bearer ${writer}`, 'content-length': String(length), 'x-snowstead-output-id': await hash(data) },
        body: data,
      }), { ...env, READ_TOKEN: reader, WRITE_TOKEN: writer }, ctx);
      expect(response.status).toBe(400);
      await waitOnExecutionContext(ctx);
      expect((await get(at)).status).toBe(404);
      expect((await put(at)).status).toBe(201);
    }
  });

  it('expires artifacts even when a previous longer retention warmed the CDN', async () => {
    const at = await path();
    expect((await put(at)).status).toBe(201);
    const ctx = createExecutionContext();
    const request = new Request(`https://cache.test${at}`, { headers: { authorization: `Bearer ${reader}` } });
    const config = { ...env, READ_TOKEN: reader, WRITE_TOKEN: writer };
    const first = await worker.fetch(request, config, ctx);
    expect(first.status).toBe(200);
    await first.arrayBuffer();
    await waitOnExecutionContext(ctx);
    await new Promise(resolve => setTimeout(resolve, 1100));
    const expiredCtx = createExecutionContext();
    const expired = await worker.fetch(request, { ...config, RETENTION_SECONDS: '1' }, expiredCtx);
    expect(expired.status).toBe(404);
    await waitOnExecutionContext(expiredCtx);
  });

  it('never lets a conflicting writer replace an action, including concurrent uploads', async () => {
    const at = await path();
    const other = new TextEncoder().encode('different but correctly hashed bytes');
    const results = await Promise.all([put(at), put(at, other)]);
    expect(results.map(result => result.status).sort()).toEqual([201, 409]);
    const result = await get(at);
    const expected = results[0].status === 201 ? data : other;
    expect(new Uint8Array(await result.arrayBuffer())).toEqual(expected);
    expect((await put(at, results[0].status === 201 ? other : data)).status).toBe(409);
    const unchanged = await get(at);
    expect(new Uint8Array(await unchanged.arrayBuffer())).toEqual(expected);
  });

  it('keeps trust namespaces separate even when their action IDs are identical', async () => {
    const at = await path();
    expect((await put(at)).status).toBe(201);
    const config = { ...env, READ_TOKEN: reader, WRITE_TOKEN: writer, CACHE_NAMESPACE: 'another-trust-domain' };
    const ctx = createExecutionContext();
    const response = await worker.fetch(new Request(`https://cache.test${at}`, { headers: { authorization: `Bearer ${reader}` } }), config, ctx);
    expect(response.status).toBe(404);
    await waitOnExecutionContext(ctx);
  });

  it('handles empty artifacts and rejects unbounded uploads and unsupported paths', async () => {
    const at = await path();
    expect((await put(at, new Uint8Array())).status).toBe(201);
    expect((await get(at)).headers.get('x-snowstead-output-id')).toBe(await hash(new Uint8Array()));
    expect((await SELF.fetch(`https://cache.test${await path()}`, {
      method: 'PUT', headers: { authorization: `Bearer ${writer}`, 'x-snowstead-output-id': await hash(data) },
      body: new ReadableStream({ start(controller) { controller.enqueue(data); controller.close(); } }),
    })).status).toBe(400);
    expect((await get('/_snowstead_go_cdn/go/test-go/actions/' + '0'.repeat(64))).status).toBe(404);
    expect((await get('/v1/actions/not-a-hash')).status).toBe(404);
  });

  it('bounds uploads and serves HEAD without an artifact body', async () => {
    const at = await path();
    const request = new Request(`https://cache.test${at}`, {
      method: 'PUT',
      headers: { authorization: `Bearer ${writer}`, 'content-length': String(64 * 1024 * 1024 + 1), 'x-snowstead-output-id': await hash(data) },
      body: data,
    });
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, { ...env, READ_TOKEN: reader, WRITE_TOKEN: writer }, ctx);
    expect(response.status).toBe(413);
    await waitOnExecutionContext(ctx);
    expect((await put(at)).status).toBe(201);
    const head = await SELF.fetch(`https://cache.test${at}`, { method: 'HEAD', headers: { authorization: `Bearer ${reader}` } });
    expect(head.status).toBe(200);
    expect(head.headers.get('content-length')).toBe(String(data.length));
    expect(await head.text()).toBe('');
    const result = await get(at);
    expect(new Uint8Array(await result.arrayBuffer())).toEqual(data);
  });
});
