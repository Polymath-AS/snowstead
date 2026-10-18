import path from "node:path";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Client } from "pg";

// Runs in Node, before any Worker starts: creates this run's database from
// the migrations, and drops it afterwards.
export async function setup(): Promise<() => Promise<void>> {
	const url = new URL(process.env.SNOWSTEAD_TEST_DATABASE ?? "");
	const name = url.pathname.slice(1);
	const server = new URL(url);
	server.pathname = "/postgres";

	const admin = new Client({ connectionString: server.toString() });
	await admin.connect();
	await admin.query(`DROP DATABASE IF EXISTS "${name}"`);
	await admin.query(`CREATE DATABASE "${name}"`);
	await admin.end();

	const client = new Client({ connectionString: url.toString() });
	await client.connect();
	await migrate(drizzle(client), { migrationsFolder: path.join(import.meta.dirname, "../migrations") });
	await client.end();

	return async () => {
		const admin = new Client({ connectionString: server.toString() });
		await admin.connect();
		await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
		await admin.end();
	};
}
