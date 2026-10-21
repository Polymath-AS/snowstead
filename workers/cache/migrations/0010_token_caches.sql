CREATE TABLE "token_caches" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "token_caches_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"token_jti" text NOT NULL,
	"cache_id" integer,
	"pattern" text,
	CONSTRAINT "token_caches_cache_or_pattern" CHECK (("token_caches"."cache_id" is null) <> ("token_caches"."pattern" is null))
);
--> statement-breakpoint
ALTER TABLE "api_tokens" ALTER COLUMN "caches_json" SET DEFAULT '[]';--> statement-breakpoint
ALTER TABLE "token_caches" ADD CONSTRAINT "token_caches_token_jti_api_tokens_jti_fk" FOREIGN KEY ("token_jti") REFERENCES "public"."api_tokens"("jti") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "token_caches" ADD CONSTRAINT "token_caches_cache_id_caches_id_fk" FOREIGN KEY ("cache_id") REFERENCES "public"."caches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "token_caches_token_cache" ON "token_caches" USING btree ("token_jti","cache_id");--> statement-breakpoint
CREATE UNIQUE INDEX "token_caches_token_pattern" ON "token_caches" USING btree ("token_jti","pattern");--> statement-breakpoint
CREATE INDEX "idx_token_caches_cache" ON "token_caches" USING btree ("cache_id");--> statement-breakpoint
-- Each entry of every token's caches_json becomes a row: "id:<n>" by its
-- cache, when that cache still exists, anything else by name or pattern.
-- caches_json stays, still written, for one release: a Worker from before
-- this one reads it.
INSERT INTO "token_caches" ("token_jti", "cache_id", "pattern")
SELECT t."jti",
	CASE WHEN e LIKE 'id:%' THEN substring(e from 4)::integer END,
	CASE WHEN e LIKE 'id:%' THEN NULL ELSE e END
FROM "api_tokens" t, jsonb_array_elements_text(t."caches_json"::jsonb) AS e
WHERE e NOT LIKE 'id:%' OR EXISTS (SELECT 1 FROM "caches" c WHERE c."id"::text = substring(e from 4))
ON CONFLICT DO NOTHING;
