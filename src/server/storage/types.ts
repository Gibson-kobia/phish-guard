/**
 * PhishGuard Database & Storage Abstraction Types
 * 
 * Defines the storage contract and entities for PhishGuard multi-tenant architecture.
 */

import {
  CanonicalSecurityEvent,
  EnrolledDevice,
  Organization,
  AuditLogEntry,
  SecurityTelemetryRecord,
  SecurityIncident,
  EnforcementMode,
  DeviceHealthStatus
} from '../../core/types';

export interface EnrollmentToken {
  id: string; // e.g. "tok_a8f921b3"
  organizationId: string;
  token: string; // Cryptographically random secret string (e.g. "pg_enroll_...")
  tokenHash: string; // SHA-256 hash for secure verification
  label: string; // e.g. "Finance Dept Laptops - Q1 2026"
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  createdAt: number;
  expiresAt: number | null; // null for no expiration
  maxUses: number | null; // null for unlimited uses
  useCount: number;
  revokedAt: number | null;
  revokedBy: string | null;
}

export type UserRole = 'SUPER_ADMIN' | 'ORG_ADMIN' | 'READ_ONLY' | 'INDIVIDUAL';

export interface AdminUser {
  id: string;
  username: string;
  name: string;
  email: string;
  role: UserRole;
  organizationId?: string; // null/undefined for super admin and individual accounts
  passwordHash: string;
  apiKey?: string;
  plan?: 'FREE' | 'PERSONAL_SHIELD' | 'FAMILY_GUARD' | 'BUSINESS_PRO' | 'ENTERPRISE';
  planStatus?: 'ACTIVE' | 'TRIAL' | 'UNCONFIGURED';
  billingInterval?: 'MONTHLY' | 'ANNUAL';
  devicesLimit?: number;
  createdAt: number;
  lastLoginAt: number;
}

export interface OrganizationStats {
  totalProtectedDevices: number;
  onlineDevices: number;
  offlineDevices: number;
  updateRequiredDevices: number;
  devicesNeedingAttention: number;
  threatsToday: number;
  blockedToday: number;
  warningsToday: number;
  totalEventsCount: number;
  topTargetedBrands: Array<{ brand: string; count: number; category: string }>;
  topThreatCategories: Array<{ category: string; count: number; percentage: number }>;
  recentEvents: CanonicalSecurityEvent[];
}

export interface QueryEventsFilter {
  organizationId?: string;
  deviceId?: string;
  riskLevel?: string;
  action?: string;
  threatCategory?: string;
  search?: string;
  sortBy?: 'newest' | 'highest_risk';
  page?: number;
  pageSize?: number;
}

export interface PaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

/**
 * Interface that all storage backends (JSON file, PostgreSQL, Cloud SQL, SQLite, etc.) must implement.
 */
export interface IDatabaseAdapter {
  init(): Promise<void> | void;

  // Organizations
  getOrganizations(): Organization[];
  getOrganizationById(organizationId: string): Organization | null;
  createOrganization(data: Partial<Organization>, actor?: string): Organization;
  updateOrganization(organizationId: string, updates: Partial<Organization>, actor?: string): Organization | null;
  deleteOrganization?(organizationId: string, actor?: string): boolean;

  // Enrollment Tokens
  createEnrollmentToken(data: {
    organizationId: string;
    label?: string;
    expiresInDays?: number | null;
    maxUses?: number | null;
    actor?: string;
  }): EnrollmentToken;
  getEnrollmentTokens(organizationId: string): EnrollmentToken[];
  getEnrollmentTokenById(tokenId: string): EnrollmentToken | null;
  validateEnrollmentToken(tokenString: string): { valid: boolean; token?: EnrollmentToken; error?: string };
  revokeEnrollmentToken(tokenId: string, actor?: string): boolean;

  // Devices & Heartbeats
  enrollDevice(data: {
    enrollmentToken: string;
    installationId: string;
    extensionVersion: string;
    browser: string;
    os: string;
    platform?: string;
    deviceName?: string;
    ip?: string;
  }): { success: boolean; device?: EnrolledDevice; error?: string; enforcementMode?: EnforcementMode; minExtensionVersion?: string; backendUrl?: string };
  getDevices(organizationId?: string): EnrolledDevice[];
  getDeviceById(deviceId: string, organizationId?: string): EnrolledDevice | null;
  getDeviceByApiKey(apiKey: string): EnrolledDevice | null;
  revokeDevice(deviceId: string, organizationId?: string, actor?: string): boolean;
  recordHeartbeat(data: {
    deviceId: string;
    installationId: string;
    extensionVersion: string;
    browser?: string;
    os?: string;
    organizationId?: string;
    ip?: string;
  }): { success: boolean; device: EnrolledDevice; enforcementMode: EnforcementMode; minExtensionVersion: string };

  // Admin Users
  getAdminUsers(organizationId?: string): AdminUser[];
  getAdminUserById(id: string): AdminUser | null;
  getAdminUserByEmail(email: string): AdminUser | null;
  createAdminUser(user: Omit<AdminUser, 'id' | 'createdAt' | 'lastLoginAt'>, actor?: string): AdminUser;
  updateAdminUser(id: string, updates: Partial<AdminUser>, actor?: string): AdminUser | null;
  deleteAdminUser(id: string, actor?: string): boolean;

  // Security Events
  ingestSecurityEvent(event: CanonicalSecurityEvent): { success: boolean; isDuplicate: boolean; eventId: string };
  ingestBatchEvents(events: CanonicalSecurityEvent[]): { ingested: number; duplicates: number };
  getSecurityEvents(filter: QueryEventsFilter): { events: CanonicalSecurityEvent[]; total: number };
  getEventById(eventId: string, organizationId?: string): CanonicalSecurityEvent | null;
  getEventsByDevice(deviceId: string, organizationId?: string): CanonicalSecurityEvent[];

  // Metrics & Stats
  getOverviewStats(organizationId?: string): OrganizationStats;
  generateCsvExport(organizationId: string): string;

  // Audit Logs
  addAuditLog(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): AuditLogEntry;
  getAuditLogs(organizationId?: string): AuditLogEntry[];

  // Session Revocation (Centralized cross-instance session revocation)
  revokeSession?(tokenHash: string, expiresAt: number, metadata?: { userId?: string; organizationId?: string }): Promise<void> | void;
  isSessionRevoked?(tokenHash: string): Promise<boolean> | boolean;
  cleanExpiredRevocations?(): Promise<number> | number;
}

export interface RevokedSessionRecord {
  tokenHash: string;
  userId?: string;
  organizationId?: string;
  revokedAt: number;
  expiresAt: number;
}
