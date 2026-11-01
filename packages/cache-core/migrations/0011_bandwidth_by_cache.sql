-- Existing rows count private NARs served before per-cache metering: they
-- keep cache 0 and are Nix.
ALTER TABLE "bandwidth_daily" ADD COLUMN "cache_id" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "bandwidth_daily" ADD COLUMN "product" text DEFAULT 'nix' NOT NULL;--> statement-breakpoint
ALTER TABLE "bandwidth_daily" ALTER COLUMN "product" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "bandwidth_daily" ADD COLUMN "public_bytes" bigint DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "bandwidth_daily" ADD COLUMN "imported_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "bandwidth_daily" DROP CONSTRAINT "bandwidth_daily_org_id_day_pk";--> statement-breakpoint
ALTER TABLE "bandwidth_daily" ADD CONSTRAINT "bandwidth_daily_org_id_cache_id_product_day_pk" PRIMARY KEY("org_id","cache_id","product","day");--> statement-breakpoint
CREATE INDEX "idx_bandwidth_daily_cache" ON "bandwidth_daily" USING btree ("cache_id","day");--> statement-breakpoint
ALTER TABLE "bandwidth_daily" ADD CONSTRAINT "bandwidth_daily_product_valid" CHECK ("bandwidth_daily"."product" IN ('nix', 'go', 'sccache'));
