/**
 * PhishGuard Environment & Deployment Configuration
 * 
 * Provides centralized environment variable resolution with explicit separation
 * between local development defaults and production deployment environments.
 */

import crypto from 'crypto';

export interface AppConfig {
  isProduction: boolean;
  port: number;
  apiBaseUrl: string;
  adminApiKey: string;
  onlineThresholdMs: number;
  defaultRetentionDays: number;
}

const isProd = process.env.NODE_ENV === 'production';

// Generate ephemeral server-side fallback if not explicitly provided in environment
const fallbackRootKey = crypto.randomBytes(32).toString('hex');

export const CONFIG: AppConfig = {
  isProduction: isProd,
  port: 3000,
  // Server-side base URL or client fallback. Defaults to current host or env var
  apiBaseUrl: process.env.PHISHGUARD_API_BASE_URL || (isProd ? '' : 'http://localhost:3000'),
  adminApiKey: process.env.PHISHGUARD_ADMIN_API_KEY || fallbackRootKey,
  // 5 minutes heartbeat threshold to mark an endpoint ONLINE vs OFFLINE
  onlineThresholdMs: 5 * 60 * 1000,
  defaultRetentionDays: 90
};
