-- Every cache is an org's now: those from before, and a self-hosted install's,
-- are the default org's, which has no storage limit. Tokens made without an
-- org are its too.
INSERT INTO "orgs" ("id", "storage_limit") VALUES ('default', NULL) ON CONFLICT ("id") DO NOTHING;--> statement-breakpoint
UPDATE "caches" SET "org_id" = 'default' WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "api_tokens" SET "org_id" = 'default' WHERE "org_id" IS NULL;--> statement-breakpoint
ALTER TABLE "caches" ALTER COLUMN "org_id" SET DEFAULT 'default';--> statement-breakpoint
ALTER TABLE "caches" ALTER COLUMN "org_id" SET NOT NULL;