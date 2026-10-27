import * as v from "valibot";
import {
	parseCacheName,
	parseCompression,
	parseFileHash,
	parseNarHash,
	parseStorePathBasename,
	parseStorePathHash,
} from "@snowstead/cache-domain";
import type { ParseError } from "@snowstead/cache-domain";
import { errorResponse, parseJsonBody } from "./responses.js";

// Request bodies and URL parts are checked against these schemas, and a
// refusal names the first thing wrong. The cache-domain parsers stay the
// source of truth for Nix's formats; each is wrapped as a schema here.

/** A string the parser accepts, as what it returns; its error message otherwise. */
function parsedBy<T extends string>(parse: (raw: string) => T | ParseError) {
	const messageFor = (raw: string) => {
		const result = parse(raw);
		// The one place a parser's answer is told apart: a string is a value.
		return typeof result === "string" ? undefined : result.message;
	};
	return v.pipe(
		// Something other than a string, or nothing, is refused as the empty string is.
		v.string(() => messageFor("") ?? "expected a string"),
		v.rawTransform<string, T>(({ dataset, addIssue, NEVER }) => {
			const result = parse(dataset.value);
			if (typeof result === "string") return result;
			addIssue({ message: result.message });
			return NEVER;
		}),
	);
}

export const CacheName = parsedBy(parseCacheName);
export const StorePathHash = parsedBy(parseStorePathHash);
export const FileHash = parsedBy(parseFileHash);
export const Compression = parsedBy(parseCompression);
// Canonical: the narinfo signature covers the nix32 form.
export const NarHash = parsedBy(parseNarHash);
export const StorePathBasename = parsedBy(parseStorePathBasename);

const ORG_ID = "org must be an org id";

/** An org id as the service running Snowstead names it, such as a WorkOS organization id. */
export const OrgId = v.pipe(v.string(ORG_ID), v.regex(/^[A-Za-z0-9_-]{1,128}$/, ORG_ID));

/**
 * The first issue as a message, led by where it is, such as paths[1], when
 * that's inside a list or map. A field's own message names the field.
 */
function firstIssue(issues: readonly v.BaseIssue<unknown>[]): string {
	const [issue] = issues;
	const path = issue.path ?? [];
	const at = path.at(-1)?.type === "object" ? path.slice(0, -1) : path;
	const where = at.map((item, i) => (item.type === "array" ? `[${String(item.key)}]` : `${i === 0 ? "" : "."}${String(item.key)}`)).join("");
	return where === "" ? issue.message : `${where}: ${issue.message}`;
}

/** `value` as `schema`, or undefined when it isn't one. */
export function valueOf<S extends v.GenericSchema>(schema: S, value: unknown): v.InferOutput<S> | undefined {
	const result = v.safeParse(schema, value);
	return result.success ? result.output : undefined;
}

/** `value` as `schema`, or a 400 naming what's wrong. */
export function parsed<S extends v.GenericSchema>(schema: S, value: unknown): v.InferOutput<S> | Response {
	for (;;) {
		const result = v.safeParse(schema, value, { abortEarly: true });
		if (result.success) return result.output;
		// A missing field fails as a missing key; given as undefined, its own
		// schema says what it needs instead. Each round fills one key.
		const missing = result.issues[0].path?.at(-1);
		// A strict object's unknown key is a key issue too, but it's there.
		if (missing?.type !== "object" || missing.origin !== "key" || missing.key in missing.input) {
			return errorResponse(firstIssue(result.issues), 400);
		}
		missing.input[missing.key] = undefined;
	}
}

/** The request's JSON body as `schema`, or a 400 naming what's wrong. */
export async function parseBody<S extends v.GenericSchema>(request: Request, schema: S): Promise<v.InferOutput<S> | Response> {
	const body = await parseJsonBody<unknown>(request);
	if (body instanceof Response) return body;
	// Valibot's objects take arrays too, and no body is an array.
	return parsed(schema, Array.isArray(body) ? undefined : body);
}
