import { sqliteTable, text, integer, primaryKey, uniqueIndex, index } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';
const DEFAULT_APP = '00000000-0000-4000-8000-000000000001';
export const applications = sqliteTable('applications',{id:text().primaryKey(),name:text().notNull(),status:text().notNull().default('active'),created_at:integer().notNull()});
export const users = sqliteTable('users', {frozen_at:integer(),
  id:text().primaryKey(),username:text().notNull(),password_hash:text().notNull(),
  status:text().notNull().default('active'),role:text().notNull().default('user'),
  subscription_until:integer().notNull().default(0),password_until:integer(),created_at:integer().notNull(),
  console_only:integer().notNull().default(0),web_approved:integer().notNull().default(0),
  application_id:text().notNull().default(DEFAULT_APP),hardware_hash:text(),email:text(),email_verified_at:integer(),
},t=>[uniqueIndex('users_site_username').on(t.username).where(sql`${t.console_only}=1 OR ${t.role}='admin'`),uniqueIndex('users_application_username').on(t.application_id,t.username).where(sql`${t.console_only}=0 AND ${t.role}='user'`)]);
export const sessions = sqliteTable('sessions', {id:text().primaryKey(),user_id:text().notNull(),audience:text().notNull(),expires_at:integer().notNull(),revoked:integer().notNull().default(0),hardware_hash:text()});
export const accessTokens = sqliteTable('access_tokens',{hash:text().primaryKey(),session_id:text().notNull(),expires_at:integer().notNull()});
export const refreshTokens = sqliteTable('refresh_tokens',{hash:text().primaryKey(),session_id:text().notNull(),used:integer().notNull().default(0)});
export const permissions = sqliteTable('permissions',{user_id:text().notNull(),permission:text().notNull()},t=>[primaryKey({columns:[t.user_id,t.permission]})]);
export const licenses = sqliteTable('licenses',{frozen_at:integer(),id:text().primaryKey(),key_hash:text().notNull().unique(),expires_at:integer().notNull(),permission:text().notNull(),hardware_bound:integer().notNull().default(0),hardware_hash:text(),user_id:text(),revoked:integer().notNull().default(0),key_ciphertext:text(),reseller_id:text(),application_id:text().notNull().default(DEFAULT_APP)},t=>[index('licenses_reseller_scope').on(t.application_id,t.reseller_id)]);
export const variables = sqliteTable('variables',{id:text().primaryKey(),name:text().notNull(),user_id:text(),value:text().notNull(),permission:text().notNull(),application_id:text().notNull().default(DEFAULT_APP)},t=>[uniqueIndex('variables_scope').on(t.application_id,t.name,sql`COALESCE(${t.user_id},'')`)]);
export const files = sqliteTable('files',{id:text().primaryKey(),storage_name:text().notNull(),permission:text().notNull(),enabled:integer().notNull().default(1),max_bytes:integer().notNull(),application_id:text().notNull().default(DEFAULT_APP)},t=>[uniqueIndex('files_application_storage').on(t.application_id,t.storage_name)]);
export const auditLogs = sqliteTable('audit_logs',{id:integer().primaryKey({autoIncrement:true}),timestamp:integer().notNull(),actor_id:text(),event:text().notNull(),target:text(),outcome:text().notNull(),application_id:text().notNull().default(DEFAULT_APP)});
export const rateLimits = sqliteTable('rate_limits',{bucket:text().primaryKey(),window_start:integer().notNull(),count:integer().notNull()});
export const migrationState = sqliteTable('migration_state',{id:text().primaryKey(),completed_at:integer().notNull()});
export const emailTokens = sqliteTable('email_tokens',{hash:text().primaryKey(),user_id:text().notNull(),purpose:text().notNull(),email:text().notNull(),credential_hash:text().notNull(),expires_at:integer().notNull(),used:integer().notNull().default(0)});

export const resellerProfiles = sqliteTable('reseller_profiles',{user_id:text().primaryKey(),max_days:integer().notNull().default(30)});
