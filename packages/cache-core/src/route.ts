import { splitReadPath, DEFAULT_ORG_SLUG } from "./cache-path.js";

/**
 * The route a request takes, as a template such as
 * `POST /_api/v1/uploads/:session/publish`: what traces and logs group by.
 * Paths carry session ids, cache names and hashes, which would otherwise
 * make every request a group of its own; paths no route serves are all
 * "unmatched", so scanners cannot add groups either.
 */
export function routeOf(method: string, pathname: string): string {
	const template = pathname.startsWith(API) ? apiTemplate(pathname) : readTemplate(pathname);
	return template ? `${method} ${template}` : "unmatched";
}

const API = "/_api/v1/";

// Each segment after one of these is a value, not part of the route.
const VALUE_AFTER: Readonly<Record<string, string>> = {
	caches: ":cache",
	uploads: ":session",
	tokens: ":jti",
	orgs: ":org",
	keys: ":key",
	"signing-keys": ":key",
	part: ":part",
};

const API_ROUTES = new Set([
	"get-missing-paths",
	"caches/:cache/upload-sessions",
	"caches/:cache/upload-sessions/batch",
	"uploads/commit",
	"uploads/:session/multipart",
	"uploads/:session/part/:part",
	"uploads/:session/blob",
	"uploads/:session/complete",
	"uploads/:session/publish",
	"admin/overview",
	"admin/tokens",
	"admin/tokens/:jti/revoke",
	"admin/caches",
	"admin/caches/:cache",
	"admin/caches/:cache/paths/delete",
	"admin/caches/:cache/purge",
	"admin/caches/:cache/delete",
	"admin/auth/sync",
	"admin/narinfo/backfill",
	"orgs/:org",
	"orgs/:org/keys",
	"orgs/:org/keys/:key/revoke",
	"orgs/:org/caches",
	"orgs/:org/caches/:cache",
	"orgs/:org/caches/:cache/purge",
	"orgs/:org/caches/:cache/paths",
	"orgs/:org/caches/:cache/delete",
	"orgs/:org/caches/:cache/signing-keys",
	"orgs/:org/caches/:cache/signing-keys/:key/activate",
	"orgs/:org/caches/:cache/paths/delete",
	"orgs/:org/tokens",
	"orgs/:org/tokens/:jti/revoke",
	"orgs/:org/audit",
]);

function apiTemplate(pathname: string): string | undefined {
	const segments = pathname.slice(API.length).split("/");
	const template = segments
		.map((segment, i) => (segment === "commit" ? segment : (VALUE_AFTER[segments[i - 1] ?? ""] ?? segment)))
		.join("/");
	return API_ROUTES.has(template) ? API + template : undefined;
}

function readTemplate(pathname: string): string | undefined {
	if (pathname === "/" || pathname === "/healthz") return pathname;
	const segments = pathname.split("/").filter(Boolean);
	// On cache.snowstead.com the Worker serves private caches under /private/.
	const prefix = segments[0] === "private" ? "/private" : "";
	if (prefix) segments.shift();
	if (segments[0] === "nar" && segments.length === 3) return `${prefix}/nar/:file`;
	const at = splitReadPath(segments);
	if (!at) return undefined;
	const cache = at.slug === DEFAULT_ORG_SLUG ? `${prefix}/:cache` : `${prefix}/:org/:cache`;
	const { rest } = at;
	if (rest.length === 1 && rest[0] === "nix-cache-info") return `${cache}/nix-cache-info`;
	if (rest.length === 1 && rest[0].endsWith(".narinfo")) return `${cache}/:hash.narinfo`;
	if (rest.length === 3 && rest[0] === "nar") return `${cache}/nar/:file`;
	return undefined;
}
