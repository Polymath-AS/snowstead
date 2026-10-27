ALTER TABLE "orgs" ADD COLUMN "custom_signing_keys" boolean DEFAULT false NOT NULL;--> statement-breakpoint
-- The default org is the operator's self-hosted namespace, not a hosted plan.
UPDATE "orgs" SET "custom_signing_keys" = true WHERE "id" = 'default';
