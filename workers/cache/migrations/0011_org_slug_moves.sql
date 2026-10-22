ALTER TABLE "orgs" ADD COLUMN "moving_from" text;--> statement-breakpoint
ALTER TABLE "orgs" ADD CONSTRAINT "orgs_moving_from_unique" UNIQUE("moving_from");