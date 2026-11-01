CREATE TABLE `applications` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
DROP INDEX `files_storage_name_unique`;--> statement-breakpoint
ALTER TABLE `files` ADD `application_id` text DEFAULT '00000000-0000-4000-8000-000000000001' NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `files_application_storage` ON `files` (`application_id`,`storage_name`);--> statement-breakpoint
DROP INDEX `users_username_unique`;--> statement-breakpoint
ALTER TABLE `users` ADD `application_id` text DEFAULT '00000000-0000-4000-8000-000000000001' NOT NULL;--> statement-breakpoint
ALTER TABLE `users` ADD `hardware_hash` text;--> statement-breakpoint
CREATE UNIQUE INDEX `users_site_username` ON `users` (`username`) WHERE "users"."console_only"=1 OR "users"."role"='admin';--> statement-breakpoint
CREATE UNIQUE INDEX `users_application_username` ON `users` (`application_id`,`username`) WHERE "users"."console_only"=0 AND "users"."role"='user';--> statement-breakpoint
DROP INDEX `variables_scope`;--> statement-breakpoint
ALTER TABLE `variables` ADD `application_id` text DEFAULT '00000000-0000-4000-8000-000000000001' NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `variables_scope` ON `variables` (`application_id`,`name`,COALESCE(`user_id`,''));--> statement-breakpoint
ALTER TABLE `audit_logs` ADD `application_id` text DEFAULT '00000000-0000-4000-8000-000000000001' NOT NULL;--> statement-breakpoint
ALTER TABLE `licenses` ADD `application_id` text DEFAULT '00000000-0000-4000-8000-000000000001' NOT NULL;
