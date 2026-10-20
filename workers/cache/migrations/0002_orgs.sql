CREATE TABLE "orgs" (
	"id" text PRIMARY KEY NOT NULL,
	"storage_limit" bigint,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "api_tokens" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "caches" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "caches" ADD CONSTRAINT "caches_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_caches_org" ON "caches" USING btree ("org_id");