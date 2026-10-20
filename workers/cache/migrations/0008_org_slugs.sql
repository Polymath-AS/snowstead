-- Cache names are an org's own now, and an org's caches are served under its
-- slug. Orgs from before get one made from their id; the service running
-- Snowstead sets proper ones. The default org's is "default", which its
-- caches' paths leave out, so they stay where they were.
ALTER TABLE "caches" DROP CONSTRAINT "caches_name_unique";--> statement-breakpoint
DROP INDEX "idx_caches_org";--> statement-breakpoint
CREATE UNIQUE INDEX "caches_org_name_unique" ON "caches" USING btree ("org_id","name");--> statement-breakpoint
ALTER TABLE "orgs" ADD COLUMN "slug" text;--> statement-breakpoint
UPDATE "orgs" SET "slug" = CASE WHEN "id" = 'default' THEN 'default'
	ELSE trim(both '-' from left(lower(regexp_replace("id", '[^A-Za-z0-9]+', '-', 'g')), 39)) END;--> statement-breakpoint
ALTER TABLE "orgs" ALTER COLUMN "slug" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "orgs" ADD CONSTRAINT "orgs_slug_unique" UNIQUE("slug");
