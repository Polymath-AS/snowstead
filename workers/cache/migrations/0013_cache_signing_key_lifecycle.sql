CREATE TABLE "cache_signing_keys" (
	"id" text PRIMARY KEY NOT NULL,
	"cache_id" integer NOT NULL,
	"signing_key_name" text NOT NULL,
	"signing_public_key" text NOT NULL,
	"signing_key_sealed" text,
	"state" text DEFAULT 'staged' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "cache_signing_keys" ADD CONSTRAINT "cache_signing_keys_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "cache_signing_keys_name" ON "cache_signing_keys" USING btree ("cache_id","signing_key_name");