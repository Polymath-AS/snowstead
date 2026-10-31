import { DurableObject, tracing } from "cloudflare:workers";
import type { RpcStub, RpcTarget } from "cloudflare:workers";
import { connect } from "./db/connection.js";
import type { Db } from "./db/connection.js";
import type { Cache } from "./db/types.js";
import { createUploadSessions, findOrg } from "./db/repository.js";
import { StreamState, streamSessionOrg } from "./upload-stream.js";
import type { StreamReceipt } from "./upload-stream.js";
import { reserveGoUpload } from "./go-cache.js";
import { reserveSccacheUpload } from "./sccache.js";
import { errorResponse } from "./responses.js";
import { errorForLog } from "./logging.js";

/** Local durable grants never wait behind remote SQL admission/publication. */
export class UploadCoordinator extends DurableObject<Env> {
	private tail: Promise<void> = Promise.resolve();
	private pending = 0;
	private readonly streams = new StreamState(this.ctx.storage);
	private sccacheLanes = {
		read: { active: 0, waiting: [] as ((admitted: boolean) => void)[] },
		write: { active: 0, waiting: [] as ((admitted: boolean) => void)[] },
	};

	/** Admission only: callbacks and payloads stay in the protocol Worker. */
	async admitSccache(laneName: "read" | "write", operation: RpcStub<RpcTarget & { run(): Promise<void> }>): Promise<boolean> {
		const arrived = Date.now();
		const lane = this.sccacheLanes[laneName];
		if (lane.active >= 8) {
			if (lane.waiting.length >= 64) return false;
			const admitted = await new Promise<boolean>(resolve => {
				const wake = (admitted: boolean) => { clearTimeout(timer); resolve(admitted); };
				const timer = setTimeout(() => {
					lane.waiting.splice(lane.waiting.indexOf(wake), 1);
					resolve(false);
				}, 2000);
				lane.waiting.push(wake);
			});
			if (!admitted) return false;
		} else {
			lane.active++;
		}
		try {
			await tracing.enterSpan("sccache_admission", async span => {
				if (span.isTraced) span.setAttributes({ "snowstead.lane": laneName, "snowstead.queue_ms": Date.now() - arrived });
				await operation.run();
			});
			return true;
		} finally {
			const next = lane.waiting.shift();
			if (next) next(true);
			else lane.active--;
		}
	}

	createStreams(org: string, rows: Parameters<typeof createUploadSessions>[1]) {
		return this.run("nix", async db => {
			if (rows.some(row => streamSessionOrg(row.id) !== org)) return errorResponse("Invalid session locator", 400);
			const policy = await findOrg(db, org);
			if (!policy) return errorResponse("Not found", 404);
			// run serializes creators. Grants, aborts, and completion can only free
			// session slots while SQL is pending, never consume this admission.
			const admission = this.streams.checkCreate(rows.length);
			if (admission) return errorResponse(admission.error, admission.status, { "retry-after": "1" });
			// Keep SQL cleanup/policy visibility, but no SQL part metadata until seal.
			await createUploadSessions(db, rows);
			const refused = this.streams.create(rows.map(row => ({ ...row, partSize: row.partSize ?? null,
				status: row.status ?? "streaming", createdAt: new Date() })), policy.storageLimit);
			if (refused) return errorResponse(refused.error, refused.status, { "retry-after": "1" });
			if (await this.ctx.storage.getAlarm() === null) await this.ctx.storage.setAlarm(Date.now() + 3600_000);
		});
	}

	getStreams(ids: readonly string[]) {
		return this.streams.get(ids);
	}

	getStreamParts(id: string) {
		return this.streams.parts(id);
	}

	pendingStreams() {
		return this.streams.pending();
	}

	reserveStreamParts(inputs: Parameters<StreamState["reserve"]>[0]) {
		return tracing.enterSpan("upload_reservation_local", () => this.streams.reserve(inputs));
	}

	sealStreams(inputs: readonly StreamReceipt[]) {
		return this.streams.seal(inputs);
	}

	sealInlineStreams(inputs: readonly StreamReceipt[]) {
		return this.streams.sealInline(inputs);
	}

	abortStream(id: string) {
		return this.streams.abort(id);
	}

	completeStreams(ids: readonly string[]) {
		this.streams.complete(ids);
	}

	async alarm() {
		this.streams.prune();
		if (this.ctx.storage.sql.exec<{ count: number }>("SELECT count(*) AS count FROM streams_v2").one().count > 0) {
			await this.ctx.storage.setAlarm(Date.now() + 3600_000);
		}
	}

	reserveGo(cache: Cache, action: string, output: string, size: number) {
		return this.run("go", db => reserveGoUpload(db, cache, action, output, size));
	}

	reserveSccache(cache: Cache, action: string, size: number) {
		return this.run("sccache", db => reserveSccacheUpload(db, cache, action, size));
	}

	private async run<T>(protocol: string, operation: (db: Db) => Promise<T>): Promise<T | Response> {
		const busy = (reason: "queue_full" | "queue_timeout", queueMs: number) => {
			console.warn({ event: "upload_admission_rejected", reason, protocol, pending: this.pending, queue_ms: queueMs });
			return errorResponse("Upload reservation queue is busy; retry", 429, { "retry-after": "1" });
		};
		if (this.pending >= 64) return busy("queue_full", 0);
		const arrived = Date.now();
		this.pending++;
		const result = this.tail.then(async () => {
			// Waiting consumes no database connection. Never time out an admitted
			// transaction: its commit outcome must be known before releasing the slot.
			const queueMs = Date.now() - arrived;
			if (queueMs > 2000) return busy("queue_timeout", queueMs);
			return tracing.enterSpan("upload_reservation", async span => {
				if (span.isTraced) span.setAttributes({ "snowstead.protocol": protocol, "snowstead.queue_ms": queueMs });
				const connection = connect(this.env.HYPERDRIVE.connectionString);
				try {
					return await operation(connection.db);
				} catch (error) {
					console.error("Upload reservation failed", errorForLog(error));
					throw new Error("Upload reservation failed");
				} finally {
					await connection.close();
				}
			});
		}).finally(() => { this.pending--; });
		// SQL/transport failure must not poison the next queued operation.
		this.tail = result.then(() => {}, () => {});
		return result;
	}
}
