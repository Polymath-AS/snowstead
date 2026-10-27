ALTER TABLE "cache_signing_keys" ADD COLUMN "managed_public_key" text;--> statement-breakpoint
ALTER TABLE "cache_signing_keys" ADD CONSTRAINT "cache_signing_keys_managed_public_key_unique" UNIQUE("managed_public_key");--> statement-breakpoint
-- Initial managed keys used to live only on caches. Imported/rotated keys
-- already have history; do not guess their provenance or change their trust.
INSERT INTO "cache_signing_keys" ("id", "cache_id", "signing_key_name", "signing_public_key", "signing_key_sealed", "managed_public_key", "state")
SELECT gen_random_uuid()::text, c.id, c.signing_key_name, c.signing_public_key, c.signing_key_sealed,
       split_part(c.signing_public_key, ':', 2), 'active'
FROM "caches" c
WHERE c.signing_key_sealed IS NOT NULL AND c.signing_public_key IS NOT NULL AND c.signing_key_name IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM "cache_signing_keys" k WHERE k.cache_id = c.id AND k.signing_public_key = c.signing_public_key);
