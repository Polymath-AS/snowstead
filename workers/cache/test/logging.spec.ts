import { describe, it, expect } from "vitest";
import { DrizzleQueryError } from "drizzle-orm";
import { errorForLog } from "../src/logging.js";
import { messageOf } from "../src/responses.js";

describe("SQL error diagnostics", () => {
	it("retains nested network codes and fixed reasons without free-form messages or credentials", () => {
		const secret = "postgres://private-user:private-password@private-host/db";
		const network = Object.assign(new Error(`connect ${secret}`), { code: "ECONNRESET" });
		const connection = new Error("Connection terminated unexpectedly", { cause: network });
		const error = new DrizzleQueryError("select $1::text", [secret], connection);
		expect(errorForLog(error)).toEqual({
			name: "DatabaseError",
			operation: "SELECT",
			causes: [{ reason: "Connection terminated unexpectedly" }, { code: "ECONNRESET" }],
		});
		expect(messageOf(error)).not.toContain(secret);
	});

	it("omits unknown driver fields and tolerates missing or cyclic causes", () => {
		const cause = Object.assign(new Error("secret value"), {
			code: "invalid code with secret", severity: "secret\nvalue", routine: "secret(value)",
			detail: "secret value", hint: "secret value", query: "select 'secret value'", params: ["secret value"],
		});
		cause.cause = cause;
		const output = errorForLog(new DrizzleQueryError("update private_table set secret = $1", ["secret value"], cause));
		expect(output).toEqual({ name: "DatabaseError", operation: "UPDATE", causes: [{}, {}, {}, {}, {}] });
		expect(errorForLog(new DrizzleQueryError("delete from private_table", []))).toEqual({
			name: "DatabaseError", operation: "DELETE", causes: [],
		});
		const other = new Error("Non-database failure");
		expect(errorForLog(other)).toBe(other);
		expect(messageOf(other)).toBe("Non-database failure");
	});
});
