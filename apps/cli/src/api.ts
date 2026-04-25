import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";

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

export interface SessionResponse {
  readonly sessionId: string;
  readonly r2Key: string;
  readonly uploadMethod: string;
  readonly expiresAt: string;
}

export async function getMissingPaths(
  client: ApiClient,
  cache: string,
  storePathHashes: string[],
): Promise<string[]> {
  const resp = await request(client, "POST", "/_api/v1/get-missing-paths", {
    cache,
    storePathHashes,
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`get-missing-paths failed (${resp.status}): ${text}`);
  }
  const data = await jsonBody<{ missing: string[] }>(resp);
  return data.missing;
}

export async function createUploadSession(
  client: ApiClient,
  cache: string,
  params: {
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
  },
): Promise<SessionResponse> {
  const resp = await request(
    client,
    "POST",
    `/_api/v1/caches/${cache}/upload-sessions`,
    params,
  );
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`create-session failed (${resp.status}): ${text}`);
  }
  return jsonBody<SessionResponse>(resp);
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

export async function uploadBlobMultipart(
  client: ApiClient,
  sessionId: string,
  filePath: string,
): Promise<void> {
  const fileInfo = await stat(filePath);
  const fileSize = Number(fileInfo.size);
  const partSize = 90 * 1024 * 1024; // 90MB parts

  await initiateMultipart(client, sessionId);

  const totalParts = Math.ceil(fileSize / partSize);
  for (let i = 0; i < totalParts; i++) {
    const start = i * partSize;
    const end = Math.min(start + partSize, fileSize);
    const length = end - start;

    const stream = createReadStream(filePath, { start, end: end - 1 });
    const webStream = ReadableStream.from(stream);

    await uploadPart(client, sessionId, i + 1, webStream, length);
  }
}

export async function publishPath(
  client: ApiClient,
  sessionId: string,
): Promise<{ published: boolean; alreadyExisted?: boolean }> {
  const resp = await request(client, "POST", `/_api/v1/uploads/${sessionId}/publish`, {});
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`publish failed (${resp.status}): ${text}`);
  }
  return jsonBody<{ published: boolean; alreadyExisted?: boolean }>(resp);
}

// ── Token Management (Admin API) ──

export interface TokenInfo {
  readonly jti: string;
  readonly subject: string;
  readonly caches: string[];
  readonly perms: string[];
  readonly createdAt: string;
  readonly expiresAt: string;
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
  readonly expiresAt: string;
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
