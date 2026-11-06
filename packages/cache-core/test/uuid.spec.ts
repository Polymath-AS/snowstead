import { describe, it, expect } from "vitest";
import { uuidv7 } from "../src/uuid.js";

describe("uuidv7", () => {
	it("leads with the millisecond timestamp, then version 7 and the RFC variant", () => {
		const ids = Array.from({ length: 200 }, () => uuidv7(0x0123456789ab));
		for (const id of ids) expect(id).toMatch(/^01234567-89ab-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
		// The rest is random.
		expect(new Set(ids).size).toBe(ids.length);
	});

	it("sorts by time across millisecond and byte boundaries", () => {
		const times = [0, 255, 256, 65_535, 65_536, 1_793_536_693_458, 2 ** 48 - 1];
		const ids = times.map((t) => uuidv7(t));
		expect([...ids].sort()).toEqual(ids);
		expect(ids[ids.length - 1].slice(0, 13)).toBe("ffffffff-ffff");
	});
});
