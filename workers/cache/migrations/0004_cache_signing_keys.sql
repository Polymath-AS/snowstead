ALTER TABLE "caches" ADD COLUMN "signing_key_name" text;--> statement-breakpoint
ALTER TABLE "caches" ADD COLUMN "signing_public_key" text;--> statement-breakpoint
ALTER TABLE "caches" ADD COLUMN "signing_key_sealed" text;