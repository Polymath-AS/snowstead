CREATE TABLE "go_entries" (
	"id" text PRIMARY KEY NOT NULL,
	"cache_id" integer,
	"generation" text NOT NULL,
	"action" text NOT NULL,
	"r2_key" text NOT NULL,
	"size" bigint NOT NULL,
	"output" text NOT NULL,
	"uploaded_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "go_entries_r2_key_unique" UNIQUE("r2_key")
);
--> statement-breakpoint
ALTER TABLE "caches" ADD COLUMN "go_generation" text DEFAULT '0' NOT NULL;--> statement-breakpoint
ALTER TABLE "go_entries" ADD CONSTRAINT "go_entries_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "go_entries_action" ON "go_entries" USING btree ("cache_id","generation","action");--> statement-breakpoint
CREATE INDEX "go_entries_expiry" ON "go_entries" USING btree ("expires_at");