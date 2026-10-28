import { env } from "cloudflare:test";
import { afterAll, describe, expect, it } from "vitest";
import { AuthorityJournal, type AuthorityCommand } from "../src/authority-journal.js";
import { resolveConfig } from "../src/config.js";

// Separate connections model separate recovery workers, not a shared Client's
// interleaved SQL transactions. All object operations use the real R2 binding;
// wrappers inject response loss/delay, never emulate conditional evaluation.
const connections: ReturnType<typeof resolveConfig>[] = [];
function worker(bucket: Pick<R2Bucket, "get" | "put"> = env.CACHE_BUCKET) {
	const config = resolveConfig(env);
	connections.push(config);
	return new AuthorityJournal(config.db, bucket);
}
afterAll(async () => { await Promise.all(connections.map((config) => config.close())); });

function command(predecessorEtag: string | null = null): AuthorityCommand {
	const operationId = crypto.randomUUID();
	return { operationId, resourceKey: `authority-test/${crypto.randomUUID()}`, predecessorEtag, payload: wire(operationId, "active") };
}

function wire(operationId: string, state: string): string {
	return JSON.stringify({ version: 2, operationId, nonce: crypto.randomUUID(), state });
}

function competing(input: AuthorityCommand): AuthorityCommand {
	return { ...command(input.predecessorEtag), resourceKey: input.resourceKey };
}

function deferred<T>() {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((done) => { resolve = done; });
	return { promise, resolve };
}

describe("durable exact-CAS authority journal", () => {
	it("persists exact commands, rejects ID reuse, and supports sequential successors without DELETE", async () => {
		const journal = worker();
		const input = command();
		const reserved = await journal.reserve(input);
		expect(await env.CACHE_BUCKET.head(input.resourceKey)).toBeNull();
		expect(JSON.parse(reserved.successor)).toMatchObject({ version: 2, operationId: input.operationId, nonce: reserved.nonce });
		expect(reserved.successor).toBe(input.payload);
		expect((await worker().reserve(input)).successor).toBe(reserved.successor);
		await expect(journal.reserve({ ...input, payload: wire(input.operationId, "different") })).rejects.toThrow("reused");
		const first = await journal.recover(input.operationId);
		expect(first.state).toBe("accepted");
		expect(first.winningEtag).toBe((await env.CACHE_BUCKET.head(input.resourceKey))!.etag);
		const next = { ...competing(input), predecessorEtag: first.winningEtag };
		const second = await journal.reserve(next);
		expect(second.nonce).not.toBe(first.nonce);
		expect((await journal.recover(next.operationId)).state).toBe("accepted");
		expect(await (await env.CACHE_BUCKET.get(input.resourceKey))!.text()).toBe(second.successor);
		// Historical acceptance survives supersession, and old recovery never PUTs.
		expect((await worker().recover(input.operationId)).state).toBe("accepted");
		expect(await (await env.CACHE_BUCKET.get(input.resourceKey))!.text()).toBe(second.successor);
	});

	it("enforces one unresolved reservation with SQL under concurrent independent workers", async () => {
		const a = worker();
		const b = worker();
		const input = command();
		const results = await Promise.allSettled([a.reserve(input), b.reserve(competing(input))]);
		expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
		expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
	});

	for (const existing of [false, true]) {
		it(`retains the barrier after unknown PUT with ${existing ? "predecessor" : "absence"} still visible`, async () => {
			const input = command();
			if (existing) {
				const original = await env.CACHE_BUCKET.put(input.resourceKey, "predecessor");
				Object.assign(input, { predecessorEtag: original!.etag });
			}
			const journal = worker({ get: env.CACHE_BUCKET.get.bind(env.CACHE_BUCKET), put: async () => { throw new Error("transport unknown"); } });
			const reserved = await journal.reserve(input);
			expect((await journal.recover(input.operationId)).state).toBe("pending");
			expect((await journal.recover(input.operationId)).state).toBe("pending");
			await expect(worker().reserve(competing(input))).rejects.toThrow("unresolved");
			const recovered = await worker().recover(input.operationId);
			expect(recovered.state).toBe("accepted");
			expect(await (await env.CACHE_BUCKET.get(input.resourceKey))!.text()).toBe(reserved.successor);
		});
	}

	it("recovers accepted PUT response loss using exact bytes before releasing the reservation", async () => {
		const input = command();
		const journal = worker({
			get: env.CACHE_BUCKET.get.bind(env.CACHE_BUCKET),
			put: async (...args) => { await env.CACHE_BUCKET.put(...args); throw new Error("lost accepted response"); },
		});
		await journal.reserve(input);
		expect((await journal.recover(input.operationId)).state).toBe("pending");
		await expect(worker().reserve(competing(input))).rejects.toThrow("unresolved");
		expect((await worker().recover(input.operationId)).state).toBe("accepted");
	});

	it("duplicate recovery workers resend exactly the persisted bytes and condition", async () => {
		const input = command();
		const entered = deferred<void>();
		const release = deferred<void>();
		const sent: { body: unknown; condition: unknown }[] = [];
		const bucket: Pick<R2Bucket, "get" | "put"> = {
			get: env.CACHE_BUCKET.get.bind(env.CACHE_BUCKET),
			put: async (...args) => {
				sent.push({ body: args[1], condition: args[2]?.onlyIf });
				if (sent.length === 2) entered.resolve();
				await release.promise;
				return env.CACHE_BUCKET.put(...args);
			},
		};
		const a = worker(bucket);
		const b = worker(bucket);
		const reserved = await a.reserve(input);
		const first = a.recover(input.operationId);
		const second = b.recover(input.operationId);
		await entered.promise;
		expect(sent).toEqual([{ body: reserved.successor, condition: { etagDoesNotMatch: "*" } }, { body: reserved.successor, condition: { etagDoesNotMatch: "*" } }]);
		release.resolve();
		await Promise.all([first, second]);
		expect((await worker().recover(input.operationId)).state).toBe("accepted");
	});

	for (const existing of [false, true]) {
		it(`one durable fence excludes a delayed original CAS against ${existing ? "ETag" : "absence"}`, async () => {
			const input = command();
			if (existing) Object.assign(input, { predecessorEtag: (await env.CACHE_BUCKET.put(input.resourceKey, "active predecessor"))!.etag });
			const entered = deferred<void>();
			const release = deferred<void>();
			let late: R2Object | null | undefined;
			const original = worker({
				get: env.CACHE_BUCKET.get.bind(env.CACHE_BUCKET),
				put: async (...args) => { entered.resolve(); await release.promise; late = await env.CACHE_BUCKET.put(...args); return late; },
			});
			await original.reserve(input);
			const pending = original.recover(input.operationId);
			await entered.promise;
			const a = worker();
			const b = worker();
			const [fenceA, fenceB] = await Promise.all([a.fence(input.operationId, wire(input.operationId, "preserved old publication")), b.fence(input.operationId, wire(input.operationId, "other proposal"))]);
			expect(fenceA.fenceSuccessor).toBe(fenceB.fenceSuccessor);
			expect(fenceA.fenceNonce).toBe(fenceB.fenceNonce);
			const excluded = await a.recover(input.operationId);
			expect(excluded.state).toBe("excluded");
			expect(excluded.winningEtag).not.toBeNull();
			release.resolve();
			await pending;
			expect(late).toBeNull();
			expect((await b.read(input.operationId)).state).toBe("excluded");
			expect(await (await env.CACHE_BUCKET.get(input.resourceKey))!.text()).toBe(fenceA.fenceSuccessor);
		});
	}

	it("records original acceptance when original wins before a fence, then permits a new explicit withdrawal", async () => {
		const input = command();
		const entered = deferred<void>();
		const release = deferred<void>();
		const original = worker({
			get: env.CACHE_BUCKET.get.bind(env.CACHE_BUCKET),
			put: async (...args) => { entered.resolve(); await release.promise; await env.CACHE_BUCKET.put(...args); throw new Error("lost response"); },
		});
		const reserved = await original.reserve(input);
		const pending = original.recover(input.operationId);
		await entered.promise;
		const recovery = worker();
		await recovery.fence(input.operationId, wire(input.operationId, "cancel preserving predecessor"));
		release.resolve();
		await pending;
		const accepted = await recovery.recover(input.operationId);
		expect(accepted.state).toBe("accepted");
		expect(await (await env.CACHE_BUCKET.get(input.resourceKey))!.text()).toBe(reserved.successor);
		expect((await recovery.fence(input.operationId, wire(input.operationId, "must not rebase"))).state).toBe("accepted");
		const withdrawalCommand = competing(input);
		const withdrawal = await recovery.reserve({ ...withdrawalCommand, predecessorEtag: accepted.winningEtag, payload: wire(withdrawalCommand.operationId, "withdrawn") });
		expect((await recovery.recover(withdrawal.operationId)).state).toBe("accepted");
		expect((await recovery.read(input.operationId)).state).toBe("accepted");
	});

	it("does not call a lost fence CAS failed publication when an in-flight original won", async () => {
		const input = command();
		const originalEntered = deferred<void>();
		const originalRelease = deferred<void>();
		const fenceEntered = deferred<void>();
		const fenceRelease = deferred<void>();
		let fenceResult: R2Object | null | undefined;
		const original = worker({
			get: env.CACHE_BUCKET.get.bind(env.CACHE_BUCKET),
			put: async (...args) => {
				originalEntered.resolve(); await originalRelease.promise;
				await env.CACHE_BUCKET.put(...args); throw new Error("lost original response");
			},
		});
		await original.reserve(input);
		const originalRequest = original.recover(input.operationId);
		await originalEntered.promise;
		const fence = worker({
			get: env.CACHE_BUCKET.get.bind(env.CACHE_BUCKET),
			put: async (...args) => {
				fenceEntered.resolve(); await fenceRelease.promise;
				fenceResult = await env.CACHE_BUCKET.put(...args); return fenceResult;
			},
		});
		await fence.fence(input.operationId, wire(input.operationId, "withdrawn"));
		const fenceRequest = fence.recover(input.operationId);
		await fenceEntered.promise;
		originalRelease.resolve();
		await originalRequest;
		fenceRelease.resolve();
		expect((await fenceRequest).state).toBe("fencing");
		expect(fenceResult).toBeNull();
		await expect(worker().reserve(competing(input))).rejects.toThrow("unresolved");
		expect((await worker().recover(input.operationId)).state).toBe("accepted");
	});

	it("recognizes a fence allocated during a recovery read rather than freezing a stale phase", async () => {
		const input = command();
		const entered = deferred<void>();
		const release = deferred<void>();
		const stale = worker({
			get: async (...args) => { entered.resolve(); await release.promise; return env.CACHE_BUCKET.get(...args); },
			put: env.CACHE_BUCKET.put.bind(env.CACHE_BUCKET),
		});
		await stale.reserve(input);
		const request = stale.recover(input.operationId);
		await entered.promise;
		const recovery = worker({
			get: env.CACHE_BUCKET.get.bind(env.CACHE_BUCKET),
			put: async (...args) => { await env.CACHE_BUCKET.put(...args); throw new Error("lost fence response"); },
		});
		await recovery.fence(input.operationId, wire(input.operationId, "withdrawn"));
		expect((await recovery.recover(input.operationId)).state).toBe("fencing");
		release.resolve();
		expect((await request).state).toBe("excluded");
	});

	it("rejects wildcard/list conditions, missing nonces, mismatched IDs, and reused fence nonces", async () => {
		const journal = worker();
		const input = command();
		for (const predecessorEtag of ["*", "", "abc,def"]) {
			await expect(journal.reserve({ ...input, predecessorEtag })).rejects.toThrow("ETag");
		}
		await expect(journal.reserve({ ...input, payload: JSON.stringify({ version: 2, operationId: input.operationId }) })).rejects.toThrow("nonce");
		await expect(journal.reserve({ ...input, payload: wire(crypto.randomUUID(), "active") })).rejects.toThrow("operation ID");
		await journal.reserve(input);
		await expect(journal.fence(input.operationId, input.payload)).rejects.toThrow("fresh nonce");
	});

	it("keeps a timed-out fence reserved and recovers its exact accepted outcome", async () => {
		const input = command();
		const journal = worker({
			get: env.CACHE_BUCKET.get.bind(env.CACHE_BUCKET),
			put: async (...args) => { await env.CACHE_BUCKET.put(...args); throw new Error("unknown fence outcome"); },
		});
		await journal.reserve(input);
		const fence = await journal.fence(input.operationId, wire(input.operationId, "withdrawn"));
		expect((await journal.recover(input.operationId)).state).toBe("fencing");
		await expect(worker().reserve(competing(input))).rejects.toThrow("unresolved");
		const recovered = await worker().recover(input.operationId);
		expect(recovered.state).toBe("excluded");
		expect(recovered.fenceSuccessor).toBe(fence.fenceSuccessor);
	});

	it("freezes an unrecognized successor without releasing the barrier", async () => {
		const journal = worker();
		const input = command();
		await journal.reserve(input);
		await env.CACHE_BUCKET.put(input.resourceKey, "unrecognized external writer");
		expect((await journal.recover(input.operationId)).state).toBe("frozen");
		await expect(worker().reserve(competing(input))).rejects.toThrow("unresolved");
		expect((await journal.fence(input.operationId, wire(input.operationId, "not a repair"))).state).toBe("frozen");
	});
});
