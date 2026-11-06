/**
 * A version 7 UUID (RFC 9562): 48 bits of Unix milliseconds, then 74 random
 * bits, so IDs sort by creation time and index well as keys. Use it for
 * identifiers, not secrets: it reveals when it was made.
 */
export function uuidv7(now: number = Date.now()): string {
	const bytes = crypto.getRandomValues(new Uint8Array(16));
	for (let i = 5, t = now; i >= 0; i--, t = Math.floor(t / 256)) bytes[i] = t % 256;
	bytes[6] = (bytes[6] & 0x0f) | 0x70;
	bytes[8] = (bytes[8] & 0x3f) | 0x80;
	const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
