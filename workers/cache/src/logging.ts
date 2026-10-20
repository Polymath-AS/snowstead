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
