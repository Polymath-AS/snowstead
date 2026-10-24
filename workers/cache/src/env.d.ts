// Secrets set via `wrangler secret put` — not in wrangler.jsonc vars.
interface Secrets {
	AUTH_TOKEN?: string;
	SIGNING_PRIVATE_KEY?: string;
	SIGNING_MASTER_KEY?: string;
	// Hosted environments use Secrets Store; local/self-hosted uses the string above.
	SIGNING_MASTER_KEY_STORE?: SecretsStoreSecret;
	R2_ACCESS_KEY_ID?: string;
	R2_SECRET_ACCESS_KEY?: string;
	R2_ENDPOINT?: string;
	JWT_SECRET?: string;
	ADMIN_SECRET?: string;
	// Cache Purge permission on the zone serving the public bucket.
	CDN_PURGE_TOKEN?: string;
}

interface Env extends Secrets {}

declare namespace Cloudflare {
	interface Env extends Secrets {}
}
