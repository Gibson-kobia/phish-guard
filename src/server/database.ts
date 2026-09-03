/**
 * PhishGuard Central Database Interface
 * 
 * Provides unified multi-tenant database abstraction.
 * Automatically chooses:
 * - SupabaseDatabaseAdapter when SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are present
 * - JsonFileDatabaseAdapter for local offline development and self-hosted environments
 */

import { IDatabaseAdapter } from './storage/types';
import { JsonFileDatabaseAdapter } from './storage/jsonFileAdapter';
import { SupabaseDatabaseAdapter } from './storage/supabaseAdapter';

function initializeDatabaseAdapter(): IDatabaseAdapter {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
  const isProduction = process.env.NODE_ENV === 'production' || !!process.env.VERCEL;

  if (supabaseUrl && supabaseKey) {
    console.log('🔌 [PhishGuard Database] Initializing Supabase PostgreSQL Adapter...');
    return new SupabaseDatabaseAdapter({ supabaseUrl, supabaseKey });
  }

  if (isProduction) {
    console.warn('⚠️ [PhishGuard Database] SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not detected in production environment. Initializing cloud adapter in bootstrap mode.');
    return new SupabaseDatabaseAdapter({ supabaseUrl: supabaseUrl || '', supabaseKey: supabaseKey || '' });
  }

  return new JsonFileDatabaseAdapter();
}

let defaultAdapter: IDatabaseAdapter = initializeDatabaseAdapter();

export const db = defaultAdapter;

export function setDatabaseAdapter(adapter: IDatabaseAdapter): void {
  defaultAdapter = adapter;
}

export function getDatabaseAdapter(): IDatabaseAdapter {
  return defaultAdapter;
}

export * from './storage/types';
export * from './storage/jsonFileAdapter';
export * from './storage/inMemoryAdapter';
export * from './storage/supabaseAdapter';
