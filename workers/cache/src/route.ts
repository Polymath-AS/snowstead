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
	"admin/tokens",
	"admin/tokens/:jti/revoke",
	"admin/caches",
	"admin/caches/:cache",
	"admin/caches/:cache/paths/delete",
	"admin/auth/sync",
	"admin/narinfo/backfill",
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
	if (segments.length === 2 && segments[1] === "nix-cache-info") return `${prefix}/:cache/nix-cache-info`;
	if (segments.length === 2 && segments[1].endsWith(".narinfo")) return `${prefix}/:cache/:hash.narinfo`;
	if (segments.length === 4 && segments[1] === "nar") return `${prefix}/:cache/nar/:file`;
	return undefined;
}
