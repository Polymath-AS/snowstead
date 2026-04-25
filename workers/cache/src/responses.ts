const JSON_HEADERS: Record<string, string> = {
	"content-type": "application/json; charset=utf-8",
	"cache-control": "no-store",
};

export function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: JSON_HEADERS,
	});
}

export function errorResponse(message: string, status: number): Response {
	return jsonResponse({ error: message }, status);
}

export async function parseJsonBody<T>(request: Request): Promise<T | Response> {
	try {
		return await request.json<T>();
	} catch {
		return errorResponse("Invalid JSON in request body", 400);
	}
}
