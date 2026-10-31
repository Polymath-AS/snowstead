import { tracing } from "cloudflare:workers";

/** Request-local upload phases, shared by production spans and local benchmarks. */
export class UploadTiming {
	private readonly durations = new Map<string, number>();

	async run<T>(phase: string, operation: () => Promise<T>): Promise<T> {
		const start = performance.now();
		try {
			return await tracing.enterSpan(`upload_${phase}`, operation);
		} finally {
			this.durations.set(phase, (this.durations.get(phase) ?? 0) + performance.now() - start);
		}
	}

	/** Nested phases and concurrent lanes overlap; these are not additive wall time. */
	header(): string {
		return [...this.durations].map(([phase, ms]) => `${phase};dur=${ms.toFixed(3)}`).join(", ");
	}
}
