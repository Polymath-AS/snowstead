import { publicationKey, type ActiveGrant, type Representation } from "./publication-protocol.js";
import type { ReadBucket } from "./read-storage.js";

type NativeBytes = {
	service: Fetcher;
	maxBytes: number;
	namespace: string;
	visibility: "public" | "private";
};

function matches(value: string, etag: string, weak: boolean): boolean {
	if (value.trim() === "*") return true;
	// Parse the whole list: commas inside opaque tags are not separators.
	if (!/^(?:W\/)?"[\x21\x23-\x7e\x80-\xff]*"(?:\s*,\s*(?:W\/)?"[\x21\x23-\x7e\x80-\xff]*")*$/.test(value.trim())) return false;
	return (value.match(/(?:W\/)?"[^"]*"/g) ?? []).some((tag) => (weak ? tag.replace(/^W\//, "") : tag) === etag);
}

function date(value: string | null): number | undefined {
	if (value === null) return undefined;
	const milliseconds = Date.parse(value);
	return Number.isFinite(milliseconds) ? Math.floor(milliseconds / 1000) : undefined;
}

function byteRange(value: string, size: number): { offset: number; length: number } | undefined {
	const match = /^bytes=(\d*)-(\d*)$/.exec(value.trim());
	if (!match || (!match[1] && !match[2]) || size === 0) return undefined;
	const first = match[1] ? Number(match[1]) : undefined;
	const last = match[2] ? Number(match[2]) : undefined;
	if ((first !== undefined && !Number.isSafeInteger(first)) || (last !== undefined && !Number.isSafeInteger(last))) return undefined;
	if (first === undefined) {
		if (!last) return undefined;
		const length = Math.min(last, size);
		return { offset: size - length, length };
	}
	if (first >= size || (last !== undefined && last < first)) return undefined;
	return { offset: first, length: Math.min(last ?? size - 1, size - 1) - first + 1 };
}

/** Serves bytes only. The caller must freshly authorize this immutable grant. */
export async function servePublication(
	request: Request,
	grant: ActiveGrant,
	representation: Representation,
	bucket: ReadBucket,
	native?: NativeBytes,
): Promise<Response> {
	const size = representation === "nar" ? grant.fileSize : grant.narinfoSize;
	const etag = representation === "nar" ? grant.narEtag : grant.narinfoEtag;
	const headers = new Headers({
		"cache-control": "no-store",
		"cloudflare-cdn-cache-control": "no-store",
		"etag": etag,
		"last-modified": new Date(grant.publishedAt * 1000).toUTCString(),
		"content-type": representation === "nar" ? "application/x-nix-nar" : "text/x-nix-narinfo",
		"accept-ranges": "bytes",
	});
	const empty = (status: number) => new Response(null, { status, headers });
	if (request.method !== "GET" && request.method !== "HEAD") {
		headers.set("allow", "GET, HEAD");
		return empty(405);
	}
	const ifMatch = request.headers.get("if-match");
	const unmodified = date(request.headers.get("if-unmodified-since"));
	if (ifMatch !== null ? !matches(ifMatch, etag, false) : unmodified !== undefined && grant.publishedAt > unmodified) return empty(412);
	const ifNoneMatch = request.headers.get("if-none-match");
	const modified = date(request.headers.get("if-modified-since"));
	if (ifNoneMatch !== null ? matches(ifNoneMatch, etag, true) : modified !== undefined && grant.publishedAt <= modified) return empty(304);

	const rangeHeader = request.headers.get("range");
	const ifRange = request.headers.get("if-range");
	const ifRangeDate = ifRange?.startsWith('"') || ifRange?.startsWith("W/") ? undefined : date(ifRange);
	// Range is defined only for GET. Even an ignored Range never fills native cache.
	// Unlike If-Unmodified-Since, an If-Range date must match exactly.
	const useRange = request.method === "GET" && rangeHeader !== null && (ifRange === null || ifRange === etag || ifRangeDate === grant.publishedAt);
	const range = useRange ? byteRange(rangeHeader!, size) : undefined;
	if (useRange && !range) {
		headers.set("content-range", `bytes */${size}`);
		return empty(416);
	}
	const key = publicationKey(grant, representation);
	headers.set("content-length", String(range?.length ?? size));
	try {
		if (request.method === "HEAD") {
			const object = await bucket.head(key);
			if (!object || object.size !== size) {
				headers.delete("content-length");
				return empty(503);
			}
			return empty(200);
		}
		if (rangeHeader === null && native && Number.isSafeInteger(native.maxBytes) && native.maxBytes > 0 && size <= native.maxBytes && /^[A-Za-z0-9_-]+$/.test(native.namespace) && (native.visibility === "public" || native.visibility === "private")) {
			// Construct a new request, never forwarding customer headers or query strings.
			const response = await native.service.fetch(new Request(`https://bytes.internal/${native.namespace}/${native.visibility}/${key}`));
			if (response.status !== 200 || response.headers.get("content-length") !== String(size) || (size > 0 && !response.body)) {
				await response.body?.cancel();
				headers.delete("content-length");
				return empty(503);
			}
			return new Response(response.body, { headers });
		}
		const object = range ? await bucket.get(key, { range }) : await bucket.get(key);
		// R2 size is the total stored object's size, including on ranged reads.
		if (!object || object.size !== size) {
			await object?.body.cancel();
			headers.delete("content-length");
			return empty(503);
		}
		if (range) headers.set("content-range", `bytes ${range.offset}-${range.offset + range.length - 1}/${size}`);
		return new Response(object.body, { status: range ? 206 : 200, headers });
	} catch {
		headers.delete("content-length");
		return empty(503);
	}
}
