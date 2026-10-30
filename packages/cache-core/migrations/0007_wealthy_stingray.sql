CREATE TABLE "nar_installations" (
	"key" text PRIMARY KEY NOT NULL,
	"operation_id" text NOT NULL,
	"source_key" text NOT NULL,
	"upload_id" text,
	"file_hash" text NOT NULL,
	"compression" text NOT NULL,
	"is_private" boolean NOT NULL,
	"file_size" bigint NOT NULL,
	"phase" text DEFAULT 'preparing' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "upload_parts" ALTER COLUMN "etag" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "upload_sessions" ALTER COLUMN "file_hash" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "upload_sessions" ADD COLUMN "part_size" integer;