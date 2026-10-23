import * as v from "valibot";

/**
 * Where a cache is, in URLs and in storage. The default org's caches (all
 * of a self-hosted install's) are at /<cache>, as caches were before orgs;
 * another org's are at /<org slug>/<cache>, so each org can have any cache
 * name, main included. Public caches are served straight from R2 by the
 * CDN, so their objects are stored under the same path Nix asks for.
 *
 * Read paths tell the two apart by their second segment: nix-cache-info, a
 * .narinfo, or nar/ follow a default-org cache's name, and a cache's name
 * follows an org's slug. Cache names can't be those, nor contain a dot.
 */

/** The default org's slug, which its caches' paths leave out. */
export const DEFAULT_ORG_SLUG = "default";

/** Slugs that would collide with the paths around caches. */
const RESERVED_SLUGS: ReadonlySet<string> = new Set([DEFAULT_ORG_SLUG, "nar", "private", "_api", "healthz"]);

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/;

const SLUG = "slug must be 1 to 39 lowercase letters, digits, or dashes, not starting or ending with a dash";

/** An org's slug. */
export const OrgSlug = v.pipe(
	v.string(SLUG),
	v.regex(SLUG_RE, SLUG),
	v.check((slug) => !RESERVED_SLUGS.has(slug), (issue) => `${String(issue.input)} is reserved`),
);

export function cachePath(orgSlug: string, cacheName: string): string {
	return orgSlug === DEFAULT_ORG_SLUG ? cacheName : `${orgSlug}/${cacheName}`;
}

/** How many segments a cache's path has: what a narinfo's relative URLs climb. */
export function pathDepth(path: string): number {
	return path.split("/").length;
}

/** A read path's cache and what's asked of it, or undefined if it names no cache. */
export function splitReadPath(segments: readonly string[]): { readonly slug: string; readonly cache: string; readonly rest: readonly string[] } | undefined {
	const [first, second] = segments;
	if (first === undefined || second === undefined) return undefined;
	if (second === "nix-cache-info" || second === "nar" || second.endsWith(".narinfo")) {
		return { slug: DEFAULT_ORG_SLUG, cache: first, rest: segments.slice(1) };
	}
	if (segments.length < 3) return undefined;
	return { slug: first, cache: second, rest: segments.slice(2) };
}
