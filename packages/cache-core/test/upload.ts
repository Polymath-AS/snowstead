import { SELF } from "cloudflare:test";
import { expect } from "vitest";

export type UploadPath = {
	storePath: string; storePathHash: string; narHash: string; narSize: number;
	compression: string; references?: string[]; deriver?: string;
};
export type Receipt = { partNumber: number; etag: string };
export type Stream = { sessionId: string; partSize: number };
export type Finalize = { sessionId: string; narHash: string; narSize: number; fileHash: string; fileSize: number; parts: Receipt[] };
export type Result = { sessionId: string; published?: boolean; alreadyExisted?: boolean; status?: number; error?: string };
export type Transport = (request: Request) => Promise<Response>;
const transport: Transport = request => SELF.fetch(request);

export function postUpload(path: string, body: unknown, token = "test-auth-token", fetcher = transport) {
	return fetcher(new Request(`http://example.com/_api/v1${path}`, {
		method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(body),
	}));
}

export async function digest(bytes: Uint8Array): Promise<string> {
	return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice()))].map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function createStream(cache: string, path: UploadPath, token = "test-auth-token", fetcher = transport): Promise<Stream> {
	const response = await postUpload(`/caches/${cache}/upload-streams/batch`, { paths: [path] }, token, fetcher);
	expect(response.status).toBe(201);
	const { sessions } = await response.json<{ sessions: Stream[] }>();
	expect(sessions[0].sessionId).toMatch(/^s2\./);
	return sessions[0];
}

export async function uploadPart(sessionId: string, bytes: Uint8Array, token = "test-auth-token", fetcher = transport, partNumber = 1): Promise<Receipt> {
	const reserved = await postUpload(`/uploads/${sessionId}/parts`, { parts: [{ partNumber, size: bytes.length }] }, token, fetcher);
	expect(reserved.status).toBe(200);
	const { parts: [grant] } = await reserved.json<{ parts: { url: string; headers: Record<string, string> }[] }>();
	const sent = await fetcher(new Request(grant.url, { method: "PUT", headers: grant.headers, body: bytes.slice() }));
	expect(sent.status).toBe(200);
	const etag = sent.headers.get("etag");
	expect(etag).toBeTruthy();
	return { partNumber, etag: etag!.replaceAll('"', "") };
}

export async function stageUpload(cache: string, path: UploadPath, bytes: Uint8Array, token = "test-auth-token", fetcher = transport): Promise<Finalize> {
	const stream = await createStream(cache, path, token, fetcher);
	const parts = [await uploadPart(stream.sessionId, bytes, token, fetcher)];
	return { sessionId: stream.sessionId, narHash: path.narHash, narSize: path.narSize, fileHash: await digest(bytes), fileSize: bytes.length, parts };
}

export async function finalizeUploads(uploads: Finalize[], token = "test-auth-token", fetcher = transport): Promise<Result[]> {
	const response = await postUpload("/uploads/finalize", { uploads }, token, fetcher);
	expect(response.status).toBe(200);
	return (await response.json<{ results: Result[] }>()).results;
}
