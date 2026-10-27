import * as v from "valibot";
import { tracing } from "cloudflare:workers";
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

// Statements are parameterized, so their text carries no values.
const MAX_TRACED_QUERY_CHARS = 2000;

/** What pg.query is given: the statement, or a config holding it. */
const QueryText = v.fallback(
	v.union([v.string(), v.pipe(v.object({ text: v.string() }), v.transform(({ text }) => text))]),
	"",
);

function queryText(config: unknown): string {
	return v.parse(QueryText, config);
}

/**
 * One client per request: Hyperdrive pools the connections to the database,
 * and a Worker may not hold sockets between requests. Nothing is built
 * until `db` is first used, and the client connects on its first query, so
 * requests that never touch the database (cache hits, nix-cache-info, NARs)
 * pay for neither: constructing a client parses the connection string.
 */
export function connect(connectionString: string): Connection {
	let client: Client | undefined;
	let db: Db | undefined;
	let connecting: Promise<unknown> | undefined;

	const open = (): Db => {
		const c = new Client({ connectionString });
		// A connection that drops is reported to the query using it; without a
		// listener the event would also surface as unhandled.
		c.on("error", () => {});
		const query = c.query.bind(c) as (...args: unknown[]) => Promise<unknown>;
		// Workers traces bindings and fetch on their own, but not Postgres over
		// Hyperdrive: each query gets a span, the first one also the connect.
		(c as { query: unknown }).query = (...args: unknown[]) =>
			tracing.enterSpan("pg_query", async (span) => {
				if (span.isTraced) {
					const text = queryText(args[0]);
					span.setAttributes({
						"db.system.name": "postgresql",
						"db.operation.name": text.split(" ", 1)[0]?.toUpperCase(),
						"db.query.text": text.slice(0, MAX_TRACED_QUERY_CHARS),
					});
				}
				connecting ??= tracing.enterSpan("pg_connect", () => c.connect());
				await connecting;
				return query(...args);
			});
		client = c;
		return drizzle(c);
	};

	const deferred: Promise<unknown>[] = [];
	return {
		get db() {
			db ??= open();
			return db;
		},
		defer: (task) => {
			deferred.push(task);
		},
		close: async () => {
			await Promise.allSettled(deferred);
			if (client && connecting) {
				await connecting.catch(() => {});
				await client.end().catch(() => {});
			}
		},
	};
}
