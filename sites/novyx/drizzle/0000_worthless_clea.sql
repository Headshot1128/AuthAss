CREATE TABLE `access_tokens` (
	`hash` text PRIMARY KEY NOT NULL,
	`session_id` text NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `audit_logs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`timestamp` integer NOT NULL,
	`actor_id` text,
	`event` text NOT NULL,
	`target` text,
	`outcome` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `files` (
	`id` text PRIMARY KEY NOT NULL,
	`storage_name` text NOT NULL,
	`permission` text NOT NULL,
	`enabled` integer DEFAULT 1 NOT NULL,
	`max_bytes` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `files_storage_name_unique` ON `files` (`storage_name`);--> statement-breakpoint
CREATE TABLE `licenses` (
	`id` text PRIMARY KEY NOT NULL,
	`key_hash` text NOT NULL,
	`expires_at` integer NOT NULL,
	`permission` text NOT NULL,
	`hardware_bound` integer DEFAULT 0 NOT NULL,
	`hardware_hash` text,
	`user_id` text,
	`revoked` integer DEFAULT 0 NOT NULL,
	`key_ciphertext` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `licenses_key_hash_unique` ON `licenses` (`key_hash`);--> statement-breakpoint
CREATE TABLE `migration_state` (
	`id` text PRIMARY KEY NOT NULL,
	`completed_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `permissions` (
	`user_id` text NOT NULL,
	`permission` text NOT NULL,
	PRIMARY KEY(`user_id`, `permission`)
);
--> statement-breakpoint
CREATE TABLE `rate_limits` (
	`bucket` text PRIMARY KEY NOT NULL,
	`window_start` integer NOT NULL,
	`count` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `refresh_tokens` (
	`hash` text PRIMARY KEY NOT NULL,
	`session_id` text NOT NULL,
	`used` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`audience` text NOT NULL,
	`expires_at` integer NOT NULL,
	`revoked` integer DEFAULT 0 NOT NULL,
	`hardware_hash` text
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`username` text NOT NULL,
	`password_hash` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`role` text DEFAULT 'user' NOT NULL,
	`subscription_until` integer DEFAULT 0 NOT NULL,
	`password_until` integer,
	`created_at` integer NOT NULL,
	`console_only` integer DEFAULT 0 NOT NULL,
	`web_approved` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_username_unique` ON `users` (`username`);--> statement-breakpoint
CREATE TABLE `variables` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`user_id` text,
	`value` text NOT NULL,
	`permission` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `variables_scope` ON `variables` (`name`,COALESCE(`user_id`,''));
