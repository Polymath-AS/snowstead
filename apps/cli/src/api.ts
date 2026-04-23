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
  const data = await resp.json() as { missing: string[] };
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
  return resp.json() as Promise<SessionResponse>;
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

export async function publishPath(
  client: ApiClient,
  sessionId: string,
): Promise<{ published: boolean; alreadyExisted?: boolean }> {
  const resp = await request(client, "POST", `/_api/v1/uploads/${sessionId}/publish`, {});
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`publish failed (${resp.status}): ${text}`);
  }
  return resp.json() as Promise<{ published: boolean; alreadyExisted?: boolean }>;
}
