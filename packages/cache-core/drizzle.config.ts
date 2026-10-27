import { defineConfig } from "drizzle-kit";

// Migrations run against the database directly, not through Hyperdrive.
export default defineConfig({
	schema: "./src/db/schema.ts",
	out: "./migrations",
	dialect: "postgresql",
	dbCredentials: {
		url: process.env.DATABASE_URL ?? "",
	},
});
