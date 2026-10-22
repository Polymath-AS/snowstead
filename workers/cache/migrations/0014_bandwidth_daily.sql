CREATE TABLE "bandwidth_daily" (
	"org_id" text NOT NULL,
	"day" date NOT NULL,
	"bytes" bigint DEFAULT 0 NOT NULL,
	CONSTRAINT "bandwidth_daily_org_id_day_pk" PRIMARY KEY("org_id","day")
);
--> statement-breakpoint
ALTER TABLE "bandwidth_daily" ADD CONSTRAINT "bandwidth_daily_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE no action ON UPDATE no action;