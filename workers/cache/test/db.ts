import { env } from "cloudflare:test";
import { afterAll } from "vitest";
import { connect } from "../src/db/connection.js";
import type { Db } from "../src/db/connection.js";

/** A connection for this test file, closed after its tests. Call at top level. */
export function testDb(): Db {
	const connection = connect(env.HYPERDRIVE.connectionString);
	afterAll(() => connection.close());
	return connection.db;
}
