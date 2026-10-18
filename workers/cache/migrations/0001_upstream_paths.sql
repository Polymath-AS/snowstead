CREATE TABLE "upstream_paths" (
	"store_path_hash" text PRIMARY KEY NOT NULL,
	"upstream" text NOT NULL,
	"found_at" timestamp with time zone DEFAULT now() NOT NULL
);
