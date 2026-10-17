import { drizzle } from "drizzle-orm/node-postgres";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import { Client } from "pg";

export type Db = NodePgDatabase;

export interface Connection {
	readonly db: Db;
	/** Database work that may outlive the response, such as audit writes. */
	defer(task: Promise<unknown>): void;
	/** Waits for deferred work, then closes the connection if it was opened. */
	close(): Promise<void>;
}

/**
 * One client per request: Hyperdrive pools the connections to the database,
 * and a Worker may not hold sockets between requests. The client connects
 * on its first query, so requests that never touch the database (cache
 * hits, nix-cache-info, NARs) open no connection at all.
 */
export function connect(connectionString: string): Connection {
	const client = new Client({ connectionString });
	// A connection that drops is reported to the query using it; without a
	// listener the event would also surface as unhandled.
	client.on("error", () => {});
	let connecting: Promise<unknown> | undefined;
	const query = client.query.bind(client) as (...args: unknown[]) => Promise<unknown>;
	(client as { query: unknown }).query = async (...args: unknown[]) => {
		connecting ??= client.connect();
		await connecting;
		return query(...args);
	};

	const deferred: Promise<unknown>[] = [];
	return {
		db: drizzle(client),
		defer: (task) => {
			deferred.push(task);
		},
		close: async () => {
			await Promise.allSettled(deferred);
			if (connecting) {
				await connecting.catch(() => {});
				await client.end().catch(() => {});
			}
		},
	};
}
