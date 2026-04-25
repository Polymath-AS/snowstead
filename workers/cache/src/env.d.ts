// Secrets set via `wrangler secret put` — not in wrangler.jsonc vars.
declare namespace Cloudflare {
	interface Env {
		AUTH_TOKEN?: string;
		SIGNING_PRIVATE_KEY?: string;
		R2_ACCESS_KEY_ID?: string;
		R2_SECRET_ACCESS_KEY?: string;
		R2_ENDPOINT?: string;
		R2_BUCKET_NAME?: string;
		JWT_SECRET?: string;
		ADMIN_SECRET?: string;
	}
}
