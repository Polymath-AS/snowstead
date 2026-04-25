CREATE TABLE `api_tokens` (
	`jti` text PRIMARY KEY NOT NULL,
	`subject` text NOT NULL,
	`caches_json` text NOT NULL,
	`perms_json` text NOT NULL,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	`expires_at` text NOT NULL,
	`created_by` text NOT NULL,
	`revoked_at` text,
	`revoked_by` text,
	`revocation_reason` text
);
--> statement-breakpoint
CREATE TABLE `audit_logs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`timestamp` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	`actor` text NOT NULL,
	`action` text NOT NULL,
	`cache_name` text,
	`detail` text DEFAULT '{}' NOT NULL,
	`ip` text,
	`status` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_audit_logs_actor` ON `audit_logs` (`actor`);--> statement-breakpoint
CREATE INDEX `idx_audit_logs_cache` ON `audit_logs` (`cache_name`);--> statement-breakpoint
CREATE INDEX `idx_audit_logs_time` ON `audit_logs` (`timestamp`);