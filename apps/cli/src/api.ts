import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import type { SessionResponse } from "@snowstead/cache-domain";
import { runPool } from "./pool.js";

export interface ApiClient {
  readonly server: string;
  readonly token: string;
}

export function createClient(server: string, token: string): ApiClient {
  return { server: server.replace(/\/$/, ""), token };
}

async function request(
  client: ApiClient,
  method: string,
  path: string,
  body?: unknown,
  headers?: Record<string, string>,
): Promise<Response> {
  const url = `${client.server}${path}`;
  const reqHeaders: Record<string, string> = {
    authorization: `Bearer ${client.token}`,
    ...headers,
  };

  const init: RequestInit = { method, headers: reqHeaders };

  if (body !== undefined && typeof body === "object" && !(body instanceof ReadableStream)) {
    reqHeaders["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  } else if (body instanceof ReadableStream) {
    init.body = body;
    init.duplex = "half";
  }

  return fetch(url, init);
}

// System boundary: Response.json() returns Promise<unknown> in Node's lib types.
// We trust the shape of our own API responses at this boundary.
async function jsonBody<T>(resp: Response): Promise<T> {
  return resp.json() as Promise<T>;
}

export interface MissingPaths {
  /** Paths to push. */
  readonly missing: string[];
  /** Paths the server knows an upstream serves, left out of missing. */
  readonly upstream: string[];
  /** Of missing, those the server has not looked up in upstreams: a client may, and skip the ones found. */
  readonly unchecked: string[];
  /** The upstreams, as substituter URLs. */
  readonly upstreams: string[];
}

export async function getMissingPaths(
  client: ApiClient,
  cache: string,
  storePathHashes: string[],
): Promise<MissingPaths> {
  const resp = await request(client, "POST", "/_api/v1/get-missing-paths", {
    cache,
    storePathHashes,
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`get-missing-paths failed (${resp.status}): ${text}`);
  }
  const data = await jsonBody<Partial<MissingPaths> & { missing: string[] }>(resp);
  return { missing: data.missing, upstream: data.upstream ?? [], unchecked: data.unchecked ?? [], upstreams: data.upstreams ?? [] };
}

interface SessionParams {
  storePath: string;
  storePathHash: string;
  narHash: string;
  narSize: number;
  fileHash: string;
  fileSize: number;
  compression: string;
  references: string[];
  deriver?: string;
  system?: string;
}

export async function uploadBlob(
  client: ApiClient,
  sessionId: string,
  filePath: string,
): Promise<void> {
  const fileInfo = await stat(filePath);
  const stream = createReadStream(filePath);
  const webStream = ReadableStream.from(stream);

  const resp = await request(client, "PUT", `/_api/v1/uploads/${sessionId}/blob`, webStream, {
    "content-type": "application/octet-stream",
    "content-length": String(fileInfo.size),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`blob upload failed (${resp.status}): ${text}`);
  }
}

/**
 * Uploads straight to R2 through a presigned URL. The signed checksum
 * header makes R2 reject any body but the one the session names.
 */
export async function uploadPresigned(
  url: string,
  headers: Record<string, string>,
  filePath: string,
): Promise<void> {
  const fileInfo = await stat(filePath);
  const resp = await putRetrying(url, () => ({
    method: "PUT",
    headers: {
      ...headers,
      "content-type": "application/x-nix-nar",
      "content-length": String(fileInfo.size),
    },
    body: ReadableStream.from(createReadStream(filePath)),
    duplex: "half",
  }));
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`presigned upload failed (${resp.status}): ${text}`);
  }
}

const PUT_ATTEMPTS = 4;

/**
 * A PUT to R2, retried with backoff while R2 asks for a slower rate (429)
 * or is briefly unavailable (503). init() makes a fresh body each attempt.
 */
async function putRetrying(url: string, init: () => RequestInit): Promise<Response> {
  for (let attempt = 1; ; attempt++) {
    const resp = await fetch(url, init());
    if ((resp.status !== 429 && resp.status !== 503) || attempt === PUT_ATTEMPTS) return resp;
    await resp.body?.cancel();
    await new Promise((resolve) => setTimeout(resolve, 250 * 2 ** attempt * (0.5 + Math.random())));
  }
}

/** Sessions for many paths of one cache, in the order given. */
export async function createUploadSessions(
  client: ApiClient,
  cache: string,
  paths: readonly SessionParams[],
): Promise<SessionResponse[]> {
  const resp = await request(client, "POST", `/_api/v1/caches/${cache}/upload-sessions/batch`, { paths });
  // Out of storage: the service says how much the push needed and what's left.
  if (resp.status === 507) {
    throw new Error((await jsonBody<{ error: string }>(resp)).error);
  }
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`create-sessions failed (${resp.status}): ${text}`);
  }
  return (await jsonBody<{ sessions: SessionResponse[] }>(resp)).sessions;
}

export interface CommitResult {
  readonly sessionId: string;
  readonly published?: boolean;
  readonly alreadyExisted?: boolean;
  readonly error?: string;
  readonly status?: number;
}

/**
 * Completes and publishes uploaded sessions; one result per session, in
 * order. Sessions uploaded in presigned parts name their parts.
 */
export async function commitUploads(
  client: ApiClient,
  sessionIds: readonly string[],
  parts?: Record<string, readonly UploadedPart[]>,
): Promise<CommitResult[]> {
  const resp = await request(client, "POST", "/_api/v1/uploads/commit", { sessionIds, parts });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`commit failed (${resp.status}): ${text}`);
  }
  return (await jsonBody<{ results: CommitResult[] }>(resp)).results;
}

export async function completeUpload(
  client: ApiClient,
  sessionId: string,
): Promise<void> {
  const resp = await request(client, "POST", `/_api/v1/uploads/${sessionId}/complete`, {});
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`complete failed (${resp.status}): ${text}`);
  }
}

const MULTIPART_THRESHOLD = 90 * 1024 * 1024; // 90MB

export function shouldUseMultipart(fileSize: number): boolean {
  return fileSize > MULTIPART_THRESHOLD;
}

export async function initiateMultipart(
  client: ApiClient,
  sessionId: string,
): Promise<{ uploadId: string; r2Key: string }> {
  const resp = await request(client, "POST", `/_api/v1/uploads/${sessionId}/multipart`, {});
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`multipart initiation failed (${resp.status}): ${text}`);
  }
  return jsonBody<{ uploadId: string; r2Key: string }>(resp);
}

export async function uploadPart(
  client: ApiClient,
  sessionId: string,
  partNumber: number,
  body: ReadableStream,
  contentLength: number,
): Promise<{ partNumber: number; etag: string }> {
  const resp = await request(
    client,
    "PUT",
    `/_api/v1/uploads/${sessionId}/part/${String(partNumber)}`,
    body,
    {
      "content-type": "application/octet-stream",
      "content-length": String(contentLength),
    },
  );
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`part upload failed (${resp.status}): ${text}`);
  }
  return jsonBody<{ partNumber: number; etag: string }>(resp);
}

// Parts of a single blob upload in parallel. Kept modest because pushPaths
// already uploads several blobs concurrently.
const PART_UPLOAD_CONCURRENCY = 4;

export async function uploadBlobMultipart(
  client: ApiClient,
  sessionId: string,
  filePath: string,
  limit: <R>(fn: () => Promise<R>) => Promise<R>,
): Promise<void> {
  const fileInfo = await stat(filePath);
  const fileSize = Number(fileInfo.size);
  const partSize = 90 * 1024 * 1024; // 90MB parts

  await initiateMultipart(client, sessionId);

  const totalParts = Math.ceil(fileSize / partSize);
  const partNumbers = Array.from({ length: totalParts }, (_, i) => i + 1);

  // Acquire the push-wide slot before opening the part's file stream.
  await runPool(partNumbers, PART_UPLOAD_CONCURRENCY, (partNumber) => limit(async () => {
    const start = (partNumber - 1) * partSize;
    const end = Math.min(start + partSize, fileSize);
    const length = end - start;

    const stream = createReadStream(filePath, { start, end: end - 1 });
    const webStream = ReadableStream.from(stream);

    await uploadPart(client, sessionId, partNumber, webStream, length);
  }));
}

export interface TokenInfo {
  readonly jti: string;
  readonly subject: string;
  readonly caches: string[];
  readonly perms: string[];
  readonly createdAt: string;
  readonly expiresAt: string | null;
  readonly createdBy: string;
  readonly revokedAt: string | null;
  readonly revokedBy: string | null;
  readonly revocationReason: string | null;
}

export interface CreateTokenResponse {
  readonly token: string;
  readonly jti: string;
  readonly subject: string;
  readonly caches: string[];
  readonly perms: string[];
  readonly expiresAt: string | null;
}

export async function createToken(
  client: ApiClient,
  params: {
    subject: string;
    caches: string[];
    perms: string[];
    expiresInDays?: number;
  },
): Promise<CreateTokenResponse> {
  const resp = await request(client, "POST", "/_api/v1/admin/tokens", params);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`token create failed (${resp.status}): ${text}`);
  }
  return jsonBody<CreateTokenResponse>(resp);
}

export async function listTokens(
  client: ApiClient,
): Promise<TokenInfo[]> {
  const resp = await request(client, "GET", "/_api/v1/admin/tokens");
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`token list failed (${resp.status}): ${text}`);
  }
  const data = await jsonBody<{ tokens: TokenInfo[] }>(resp);
  return data.tokens;
}

export async function revokeToken(
  client: ApiClient,
  jti: string,
  reason: string,
): Promise<void> {
  const resp = await request(client, "POST", `/_api/v1/admin/tokens/${jti}/revoke`, { reason });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`token revoke failed (${resp.status}): ${text}`);
  }
}

export interface CacheInfo {
  readonly name: string;
  readonly private: boolean;
  readonly protocols: CacheProtocol[];
  readonly createdAt: string;
}

export type CacheProtocol = "nix" | "go";

/** Creates or updates a cache. New caches require explicit protocols. */
export async function createCache(
  client: ApiClient,
  name: string,
  isPrivate?: boolean,
  protocols?: CacheProtocol[],
): Promise<CacheInfo & { readonly created: boolean; readonly changed: boolean }> {
  const resp = await request(client, "POST", "/_api/v1/admin/caches", { name, private: isPrivate, protocols });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`cache create failed (${resp.status}): ${text}`);
  }
  return jsonBody<CacheInfo & { created: boolean; changed: boolean }>(resp);
}

export async function listCaches(
  client: ApiClient,
): Promise<CacheInfo[]> {
  const resp = await request(client, "GET", "/_api/v1/admin/caches");
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`cache list failed (${resp.status}): ${text}`);
  }
  const data = await jsonBody<{ caches: CacheInfo[] }>(resp);
  return data.caches;
}

export interface UploadedPart {
  readonly partNumber: number;
  readonly etag: string;
}

/**
 * Uploads a file in presigned parts, partSize bytes each but the last, at
 * most `limit` of them at once across the whole push; returns their ETags.
 */
export async function uploadPresignedParts(
  parts: ReadonlyArray<{ readonly partNumber: number; readonly url: string }>,
  partSize: number,
  filePath: string,
  limit: <R>(fn: () => Promise<R>) => Promise<R>,
): Promise<UploadedPart[]> {
  const fileSize = Number((await stat(filePath)).size);
  return Promise.all(parts.map((part) => limit(async () => {
    const start = (part.partNumber - 1) * partSize;
    const end = Math.min(start + partSize, fileSize);
    const resp = await putRetrying(part.url, () => ({
      method: "PUT",
      headers: { "content-length": String(end - start) },
      body: ReadableStream.from(createReadStream(filePath, { start, end: end - 1 })),
      duplex: "half",
    }));
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`part ${String(part.partNumber)} upload failed (${resp.status}): ${text}`);
    }
    const etag = resp.headers.get("etag");
    if (!etag) throw new Error(`part ${String(part.partNumber)} upload returned no ETag`);
    return { partNumber: part.partNumber, etag };
  })));
}
