// conexión sqlite compartida (singleton) con los defaults de la plataforma
import { createSqliteDb, type SqliteDbHandle } from '@platform/db';
import type { BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import * as schema from './schema.js';

export type DbSchema = typeof schema;
export type Db = BetterSQLite3Database<DbSchema>;

let handle: SqliteDbHandle<DbSchema> | null = null;

export function getDb(): Db {
  if (!handle) {
    handle = createSqliteDb({
      schema,
      defaultPath: './data/oauth.db',
      migrationsCandidates: ['src/db/migrations', 'dist/db/migrations'],
      logTag: 'oauth-db',
    });
  }
  return handle.db;
}

export function closeDb(): void {
  handle?.close();
  handle = null;
}
