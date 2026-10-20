ALTER TABLE "audit_logs" ADD COLUMN "org_id" text;--> statement-breakpoint
CREATE INDEX "idx_audit_logs_org" ON "audit_logs" USING btree ("org_id","id");