import { parseCacheName, parseFileHash, parseCompression, parseStorePathHash } from "@snowstead/cache-domain";
import { splitReadPath, cachePath } from "./cache-path.js";
import { extractCredential, tokenIsActive } from "./credentials.js";
import { verifyJwt, hasPermission, hasCacheAccess, isOrgsToken } from "./jwt.js";
import {
	RouteRecord, CacheStatus, PathGrant, LegacyWitness,
	readAuthority, routeKey, statusKey, grantKey, witnessKey,
} from "./publication-protocol.js";
import type { ActiveGrant, Representation } from "./publication-protocol.js";
import { servePublication } from "./publication-http.js";
import type { ReadBucket } from "./read-storage.js";

/** Deliberately no database, admin secret, WorkOS, or KV binding. */
export interface DownloadConfig {
	readonly authority: Pick<ReadBucket, "get">;
	readonly publicBucket: ReadBucket;
	readonly privateBucket: ReadBucket;
	readonly jwtSecret: string;
	readonly native?: { service: Fetcher; maxBytes: number; namespace: string };
}

function denied(status: number, message: string, headers: Record<string, string> = {}): Response {
	return new Response(message, {
		status,
		headers: { "cache-control": "no-store", "cloudflare-cdn-cache-control": "no-store", ...headers },
	});
}

async function authorizePrivate(request: Request, config: DownloadConfig, status: CacheStatus): Promise<Response | undefined> {
	const token = extractCredential(request);
	const unauthorized = () => denied(401, "Unauthorized", { "www-authenticate": 'Basic realm="snowstead"' });
	if (!token || !config.jwtSecret) return unauthorized();
	const verified = await verifyJwt(token, config.jwtSecret);
	if (verified.kind !== "ok") return unauthorized();
	const claims = verified.claims;
	if (!await tokenIsActive(config.authority, claims)) return unauthorized();
	if (!isOrgsToken(claims, status.orgId) || !hasPermission(claims, "pull") ||
		!hasCacheAccess(claims, { id: status.cacheId, name: status.name })) return denied(403, "Forbidden");
	return undefined;
}

/** Canonical core paths only: /<org>/<cache>/… or /<default-cache>/…. */
export async function handleDownload(request: Request, config: DownloadConfig): Promise<Response> {
	try {
		if (request.method !== "GET" && request.method !== "HEAD") return denied(405, "Method Not Allowed", { allow: "GET, HEAD" });
		const url = new URL(request.url);
		// Never reinterpret encoded separators, doubled separators or alternate
		// path spellings as an authority key. Queries do not select objects.
		if (url.pathname.includes("%") || url.pathname.includes("//")) return denied(404, "Not Found");
		const at = splitReadPath(url.pathname.slice(1).split("/"));
		if (!at || typeof parseCacheName(at.cache) !== "string" ||
			!(/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/.test(at.slug))) return denied(404, "Not Found");
		const path = cachePath(at.slug, at.cache);
		const route = await readAuthority(config.authority, routeKey(path), RouteRecord);
		if (!route || route.state !== "active" || route.path !== path) return denied(404, "Not Found");
		const status = await readAuthority(config.authority, statusKey(route.cacheId), CacheStatus);
		if (!status || status.state !== "active" || status.cacheId !== route.cacheId ||
			status.orgId !== route.orgId || status.name !== at.cache) return denied(404, "Not Found");
		if (status.visibility === "private") {
			const refused = await authorizePrivate(request, config, status);
			if (refused) return refused;
		}
		const rest = at.rest;
		if (rest.length === 1 && rest[0] === "nix-cache-info") {
			const body = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n";
			return new Response(request.method === "HEAD" ? null : body, { headers: {
				"content-type": "text/x-nix-cache-info", "content-length": String(body.length),
				"cache-control": "no-store", "cloudflare-cdn-cache-control": "no-store",
			} });
		}
		let hash: string;
		let publication: string | undefined;
		let fileHash: string | undefined;
		let compression: string | undefined;
		let representation: Representation;
		if (rest.length === 1 && rest[0].endsWith(".narinfo")) {
			hash = rest[0].slice(0, -8);
			representation = "narinfo";
		} else if (rest.length === 5 && rest[0] === "nar" && rest[1] === "v2" && rest[4].endsWith(".nar")) {
			hash = rest[2]; publication = rest[3]; fileHash = rest[4].slice(0, -4);
			representation = "nar";
		} else if (rest.length === 3 && rest[0] === "nar" && rest[2].endsWith(".nar")) {
			fileHash = rest[1]; compression = rest[2].slice(0, -4);
			if (typeof parseFileHash(fileHash) !== "string" || typeof parseCompression(compression) !== "string") return denied(404, "Not Found");
			const witness = await readAuthority(config.authority, witnessKey(status.cacheId, status.epoch, fileHash, compression), LegacyWitness);
			if (!witness || witness.cacheId !== status.cacheId || witness.orgId !== status.orgId ||
				witness.epoch !== status.epoch || witness.fileHash !== fileHash || witness.compression !== compression) return denied(404, "Not Found");
			hash = witness.storePathHash; publication = witness.publicationId;
			representation = "nar";
		} else return denied(404, "Not Found");
		if (typeof parseStorePathHash(hash) !== "string") return denied(404, "Not Found");
		const grant = await readAuthority(config.authority, grantKey(status.cacheId, status.epoch, hash), PathGrant);
		if (!grant || grant.state !== "active" || grant.cacheId !== status.cacheId || grant.orgId !== status.orgId ||
			grant.epoch !== status.epoch || grant.storePathHash !== hash ||
			(publication !== undefined && grant.publicationId !== publication) ||
			(fileHash !== undefined && grant.fileHash !== fileHash) ||
			(compression !== undefined && grant.compression !== compression)) return denied(404, "Not Found");
		return await bytes(request, config, status, grant, representation);
	} catch {
		// Authority outages/corruption never fall through to a warm byte cache.
		return denied(503, "Cache temporarily unavailable");
	}
}

async function bytes(request: Request, config: DownloadConfig, status: CacheStatus, grant: ActiveGrant, representation: Representation): Promise<Response> {
	const bucket = status.visibility === "private" ? config.privateBucket : config.publicBucket;
	const native = config.native ? { ...config.native, visibility: status.visibility } : undefined;
	const response = await servePublication(request, grant, representation, bucket, native);
	if (status.visibility === "private") response.headers.set("cache-control", "private, no-store");
	return response;
}
