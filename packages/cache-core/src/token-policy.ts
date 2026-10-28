import { and, eq, inArray, sql, asc } from "drizzle-orm";
import * as v from "valibot";
import { AuthorityJournal } from "./authority-journal.js";
import type { AuthorityOperation } from "./authority-journal.js";
import type { WorkerConfig } from "./config.js";
import type { TokenClaims } from "./jwt.js";
import { verifyJwt, cacheIdEntry } from "./jwt.js";
import type { Db } from "./db/connection.js";
import { claimsDigest } from "./credentials.js";
import { authorityJournal, apiTokens, tokenCaches, DEFAULT_ORG_ID } from "./db/schema.js";
import { TokenPolicy, KeyPolicy, LEGACY_KEY_POLICY, tokenKey, MAX_AUTHORITY_BYTES } from "./publication-protocol.js";

export type PolicyResult =
	| { state: "committed" }
	| { state: "pending" | "frozen"; operationId: string };

function outcome(operation: AuthorityOperation): PolicyResult {
	return operation.state === "accepted" || operation.state === "excluded"
		? { state: "committed" }
		: { state: operation.state === "frozen" ? "frozen" : "pending", operationId: operation.operationId };
}

/**
 * Called only by issuance/enrollment/revocation control paths, never on reads.
 * Revoked JTIs cannot be enrolled again. An unresolved creation is fenced by
 * revocation, rather than being assumed absent after a lost PUT response.
 */
async function transition(config: WorkerConfig, jti: string | undefined, digest: string | undefined,
	validate?: (db: Db) => Promise<void>): Promise<PolicyResult> {
	const key = jti === undefined ? LEGACY_KEY_POLICY : tokenKey(jti);
	const parse = (value: unknown) => jti === undefined ? v.parse(KeyPolicy, value) : v.parse(TokenPolicy, value);
	// At most one original win followed by a tombstone is needed. Bound work
	// per invocation; an uncertain outcome remains a durable pending command.
	for (let round = 0; round < 3; round++) {
		const work = await config.db.transaction(async (tx) => {
			// Metadata only, no bulk transfer. Serialize observing a predecessor
			// with allocating its command; this lock is NOT an in-flight PUT fence.
			await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${key}, 0))`);
			await validate?.(tx);
			const [pending] = await tx.select().from(authorityJournal).where(and(
				eq(authorityJournal.resourceKey, key), inArray(authorityJournal.state, ["pending", "fencing", "frozen"]),
			));
			const journal = new AuthorityJournal(tx, config.bucket);
			if (pending) {
				if (digest === undefined && pending.state === "pending") {
					const old = parse(JSON.parse(pending.successor));
					await journal.fence(pending.operationId, JSON.stringify({ ...old, state: "revoked", nonce: crypto.randomUUID() }));
				}
				return pending.operationId;
			}
			const current = await config.bucket.get(key);
			if (current && current.size > MAX_AUTHORITY_BYTES) { await current.body.cancel(); throw new Error("Oversized token policy"); }
			const policy = current ? parse(await current.json()) : undefined;
			if (policy && "jti" in policy && policy.jti !== jti) throw new Error("Token policy identity mismatch");
			if (policy?.state === "revoked") {
				if (digest !== undefined) throw new Error(jti === undefined ? "A revoked verifier key cannot be initialized again" : "A revoked JTI cannot be enrolled again");
				return undefined;
			}
			if (digest !== undefined && policy) {
				if ("claimsDigest" in policy && policy.claimsDigest !== digest) throw new Error("Token enrollment identity mismatch");
				return undefined;
			}
			const operationId = crypto.randomUUID();
			const target = parse({
				version: 2, operationId, nonce: crypto.randomUUID(),
				state: digest === undefined ? "revoked" : "active",
				...(jti === undefined ? { keyId: "legacy-hs256" } : {
					jti, claimsDigest: digest ?? (policy && "claimsDigest" in policy ? policy.claimsDigest : "0".repeat(64)),
				}),
			});
			await journal.reserve({ operationId, resourceKey: key, predecessorEtag: current?.etag ?? null, payload: JSON.stringify(target) });
			return operationId;
		});
		if (work === undefined) return { state: "committed" };
		const result = outcome(await new AuthorityJournal(config.db, config.bucket).recover(work));
		if (result.state !== "committed") return result;
		// Observe the winner before claiming the requested state. In particular,
		// acceptance of an earlier active policy is not completion of revocation.
	}
	throw new Error("Token policy requires further reconciliation");
}

/** Issuance has exact claims; legacy enrollment must first validate inventory. */
export async function enrollToken(config: WorkerConfig, claims: TokenClaims): Promise<PolicyResult> {
	return transition(config, claims.jti, await claimsDigest(claims));
}

/** A permanent tombstone, including for tokens within exp + verifier skew. */
export async function revokeTokenPolicy(config: WorkerConfig, jti: string): Promise<PolicyResult> {
	return transition(config, jti, undefined);
}

/** Operator-only opt-in. Never call from auth, reads, or automatic startup. */
export async function initializeVerifierKey(config: WorkerConfig): Promise<PolicyResult> {
	if (!config.jwtSecret) throw new Error("JWT verifier secret is not configured");
	return transition(config, undefined, "active");
}

/** Permanent, including before initialization; secret rotation cannot undo it. */
export async function revokeVerifierKey(config: WorkerConfig): Promise<PolicyResult> {
	return transition(config, undefined, undefined);
}

/**
 * Controlled migration only: the signed credential AND SQL inventory must agree.
 * SQL's creation timestamp is not the JWT iat; allow the verifier's 60s skew
 * around it, but require the exact recorded expiry (including no expiry).
 */
export async function enrollLegacyToken(config: WorkerConfig, token: string): Promise<PolicyResult> {
	if (!config.jwtSecret) throw new Error("JWT verifier secret is not configured");
	const verified = await verifyJwt(token, config.jwtSecret);
	if (verified.kind !== "ok") throw new Error("Invalid legacy token");
	const claims = verified.claims;
	const digest = await claimsDigest(claims);
	return transition(config, claims.jti, digest, async (db) => {
		const [inventory] = await db.select().from(apiTokens).where(eq(apiTokens.jti, claims.jti)).for("share");
		const entries = await db.select().from(tokenCaches).where(eq(tokenCaches.tokenJti, claims.jti)).orderBy(tokenCaches.id);
		const caches = entries.map((entry) => entry.cacheId === null ? entry.pattern : cacheIdEntry(entry.cacheId));
		if (!inventory || inventory.revokedAt !== null ||
			(await config.authKv.get(`revoked/${claims.jti}`)) !== null) throw new Error("Legacy token missing or revoked in inventory");
		if (claims.exp !== undefined && Date.now() / 1000 >= claims.exp + 60) throw new Error("Expired legacy token");
		if (inventory.subject !== claims.sub || (inventory.orgId ?? DEFAULT_ORG_ID) !== (claims.org ?? DEFAULT_ORG_ID) ||
			Math.abs(inventory.createdAt.getTime() / 1000 - claims.iat) > 60 ||
			(inventory.expiresAt?.getTime() ?? null) !== (claims.exp === undefined ? null : claims.exp * 1000) ||
			JSON.stringify(caches) !== JSON.stringify(claims.caches) ||
			JSON.stringify(JSON.parse(inventory.permsJson)) !== JSON.stringify(claims.perms)) {
			throw new Error("Legacy token inventory mismatch");
		}
	});
}

/**
 * Bounded operator/scheduled recovery, not a read-path initializer. Accepted
 * originals whose revocation fence lost remain work until a tombstone command
 * exists, so a crash between settlement and follow-up cannot lose revocation.
 */
export async function recoverTokenPolicies(config: WorkerConfig, limit = 25): Promise<PolicyResult[]> {
	if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error("Invalid policy recovery limit");
	const rows = await config.db.select().from(authorityJournal).where(and(
		sql`(${authorityJournal.resourceKey} like 'authority/v2/tokens/%' or ${authorityJournal.resourceKey} = ${LEGACY_KEY_POLICY})`,
		sql`(${authorityJournal.state} in ('pending', 'fencing', 'frozen') or
			(${authorityJournal.state} = 'accepted' and ${authorityJournal.fenceSuccessor} is not null and not exists (
				select 1 from authority_journal successor where successor.resource_key = ${authorityJournal.resourceKey}
				and successor.operation_id <> ${authorityJournal.operationId}
				and successor.successor::jsonb ->> 'state' = 'revoked')))`,
	)).orderBy(sql`case when ${authorityJournal.state} = 'frozen' then 1 else 0 end`,
		asc(authorityJournal.createdAt), asc(authorityJournal.operationId)).limit(limit);
	const results: PolicyResult[] = [];
	for (const row of rows) {
		const recovered = await new AuthorityJournal(config.db, config.bucket).recover(row.operationId);
		if (recovered.state === "accepted" && recovered.fenceSuccessor !== null) {
			const target = JSON.parse(recovered.fenceSuccessor);
			results.push(row.resourceKey === LEGACY_KEY_POLICY
				? await revokeVerifierKey(config) : await revokeTokenPolicy(config, v.parse(TokenPolicy, target).jti));
		} else results.push(outcome(recovered));
	}
	return results;
}
