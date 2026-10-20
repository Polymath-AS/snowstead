// Secrets set via `wrangler secret put` — not in wrangler.jsonc vars.
interface Secrets {
	AUTH_TOKEN?: string;
	SIGNING_PRIVATE_KEY?: string;
	SIGNING_MASTER_KEY?: string;
	R2_ACCESS_KEY_ID?: string;
	R2_SECRET_ACCESS_KEY?: string;
	R2_ENDPOINT?: string;
	R2_BUCKET_NAME?: string;
	R2_PUBLIC_BUCKET_NAME?: string;
	JWT_SECRET?: string;
	ADMIN_SECRET?: string;
}

interface Env extends Secrets {}

declare namespace Cloudflare {
	interface Env extends Secrets {}
}
