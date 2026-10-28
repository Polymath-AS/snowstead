CREATE TABLE "cache_protocols" (
	"cache_id" integer NOT NULL,
	"protocol" text NOT NULL,
	CONSTRAINT "cache_protocols_cache_id_protocol_pk" PRIMARY KEY("cache_id","protocol"),
	CONSTRAINT "cache_protocols_protocol_valid" CHECK ("cache_protocols"."protocol" IN ('nix', 'go'))
);
--> statement-breakpoint
ALTER TABLE "cache_protocols" ADD CONSTRAINT "cache_protocols_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
-- Existing caches already serve both products; preserve that on upgrade.
INSERT INTO "cache_protocols" ("cache_id", "protocol")
SELECT "id", protocol FROM "caches" CROSS JOIN (VALUES ('nix'), ('go')) AS enabled(protocol);
