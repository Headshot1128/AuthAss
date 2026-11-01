CREATE TABLE `reseller_profiles` (
	`user_id` text PRIMARY KEY NOT NULL,
	`max_days` integer DEFAULT 30 NOT NULL
);
--> statement-breakpoint
ALTER TABLE `licenses` ADD `reseller_id` text;