import { drizzle } from "drizzle-orm/node-postgres";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

export type Db = NodePgDatabase;

export interface Connection {
	readonly db: Db;
	/** Database work that may outlive the response, such as audit writes. */
	defer(task: Promise<unknown>): void;
	/** Waits for deferred work, then releases the connections. */
	close(): Promise<void>;
}

/**
 * A pool for one request. Hyperdrive pools connections to the database
 * across requests, so a Worker opens its own per request rather than
 * holding sockets between requests, which the runtime does not allow.
 */
export function connect(connectionString: string): Connection {
	const pool = new Pool({ connectionString, max: 5 });
	// An idle connection that drops (its socket cancelled when a request
	// ends) is replaced on next use; queries in flight report their own
	// errors. Without a listener the event would surface as unhandled.
	pool.on("error", () => {});
	const deferred: Promise<unknown>[] = [];
	return {
		db: drizzle(pool),
		defer: (task) => {
			deferred.push(task);
		},
		close: async () => {
			await Promise.allSettled(deferred);
			await pool.end();
		},
	};
}
