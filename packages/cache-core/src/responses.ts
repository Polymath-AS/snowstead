import { DrizzleQueryError } from "drizzle-orm";
import { errorForLog } from "./logging.js";

const JSON_HEADERS: Record<string, string> = {
	"content-type": "application/json; charset=utf-8",
	"cache-control": "no-store",
};

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { ...JSON_HEADERS, ...headers },
	});
}

export function errorResponse(message: string, status: number, headers: Record<string, string> = {}): Response {
	return jsonResponse({ error: message }, status, headers);
}

export async function parseJsonBody<T>(request: Request): Promise<T | Response> {
	try {
		return await request.json<T>();
	} catch {
		return errorResponse("Invalid JSON in request body", 400);
	}
}

/** What went wrong, for a log line or an error list. */
export function messageOf(err: unknown): string {
	if (err instanceof DrizzleQueryError) return JSON.stringify(errorForLog(err));
	return err instanceof Error ? err.message : String(err);
}
