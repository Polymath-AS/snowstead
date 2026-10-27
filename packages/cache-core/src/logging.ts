import { DrizzleQueryError } from "drizzle-orm";

/** SQL errors can echo values in both Drizzle's wrapper and Postgres's message/detail. */
export function errorForLog(error: unknown): unknown {
	if (!(error instanceof DrizzleQueryError)) return error;
	const causes: Record<string, string>[] = [];
	let cause: unknown = error.cause;
	// Bound traversal in case a driver supplies a cyclic cause chain.
	for (let depth = 0; depth < 5 && cause instanceof Error; depth++) {
		const fields: Record<string, string> = {};
		for (const key of ["code", "severity", "routine"] as const) {
			const value = (cause as Error & Record<string, unknown>)[key];
			if (typeof value === "string" && /^[A-Za-z0-9_]{1,64}$/.test(value)) fields[key] = value;
		}
		// These fixed driver messages add context when there is no SQLSTATE.
		if (["Connection terminated unexpectedly", "Connection terminated", "Connection terminated due to connection timeout", "Client has encountered a connection error and is not queryable"].includes(cause.message)) {
			fields.reason = cause.message;
		}
		causes.push(fields);
		cause = cause.cause;
	}
	return {
		name: "DatabaseError",
		operation: /^\s*([a-z]+)/i.exec(error.query)?.[1]?.toUpperCase(),
		causes,
	};
}

/**
 * One line per request worth recording. Logged as an object, not a string,
 * so Workers Logs indexes its fields and can group requests by route.
 */
export function logRequest(
	request: Request,
	response: Response,
	startTime: number,
	route: string,
): void {
	console.log({
		route,
		method: request.method,
		path: new URL(request.url).pathname,
		status: response.status,
		duration_ms: Date.now() - startTime,
		cf_ray: request.headers.get("cf-ray") ?? undefined,
	});
}
