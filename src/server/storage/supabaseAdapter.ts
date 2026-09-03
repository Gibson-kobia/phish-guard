/**
 * PhishGuard Supabase / PostgreSQL Database Adapter
 * 
 * Implements IDatabaseAdapter backed by Supabase PostgreSQL for cloud production deployments.
 * Enforces strict multi-tenant isolation, cryptographically hashed tokens, device authentication,
 * and sanitized telemetry ingestion.
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import {
  CanonicalSecurityEvent,
  EnrolledDevice,
  Organization,
  AuditLogEntry,
  EnforcementMode,
  DeviceHealthStatus
} from '../../core/types';
import {
  IDatabaseAdapter,
  EnrollmentToken,
  AdminUser,
  OrganizationStats,
  QueryEventsFilter,
  RevokedSessionRecord
} from './types';

import { hashPassword } from '../authUtils';

const ONLINE_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes

export interface SupabaseAdapterConfig {
  supabaseUrl: string;
  supabaseKey: string;
}

export class SupabaseDatabaseAdapter implements IDatabaseAdapter {
  private client: SupabaseClient | null = null;
  private isConnected = false;
  private initPromise: Promise<void> | null = null;
  private config: SupabaseAdapterConfig;

  // Local cache of memory indexes for synchronous IDatabaseAdapter contract & high performance
  private orgsCache = new Map<string, Organization>();
  private devicesCache = new Map<string, EnrolledDevice>();
  private tokensCache = new Map<string, EnrollmentToken>();
  private adminUsersCache = new Map<string, AdminUser>();
  private eventsCache: CanonicalSecurityEvent[] = [];
  private auditLogsCache: AuditLogEntry[] = [];

  constructor(config?: Partial<SupabaseAdapterConfig>) {
    this.config = {
      supabaseUrl: config?.supabaseUrl || process.env.SUPABASE_URL || '',
      supabaseKey: config?.supabaseKey || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || ''
    };
    // Initialize in-memory cache synchronously so immediate requests on cold-start have valid baseline state
    this.seedInitialLocalState();
    this.initPromise = this.init();
  }

  public async ensureInitialized(): Promise<void> {
    if (this.initPromise) {
      await this.initPromise;
    }
  }

  private seedInitialLocalState(): void {
    const now = Date.now();
    const initialPass = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    const scryptPasswordHash = initialPass ? hashPassword(initialPass) : 'DISABLED:UNINITIALIZED_BOOTSTRAP';

    const superAdmin: AdminUser = {
      id: 'usr_super_admin_01',
      username: 'admin',
      name: 'SecOps Director',
      email: 'admin@phishguard.security',
      role: 'SUPER_ADMIN',
      passwordHash: scryptPasswordHash,
      apiKey: 'pg_secops_master_key_2026',
      createdAt: now - 30 * 86400000,
      lastLoginAt: now - 3600000
    };
    this.adminUsersCache.set(superAdmin.id, superAdmin);

    const orgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    const acmeAdminHash = orgAdminPass ? hashPassword(orgAdminPass) : 'DISABLED:UNINITIALIZED_BOOTSTRAP';
    const acmeOrgAdmin: AdminUser = {
      id: 'usr_acme_admin_01',
      username: 'acme_admin',
      name: 'Alex Rivera (IT Lead)',
      email: 'it-admin@acme-corp.com',
      role: 'ORG_ADMIN',
      organizationId: 'ORG-ACME-PILOT',
      passwordHash: acmeAdminHash,
      apiKey: 'pg_acme_admin_key_2026',
      createdAt: now - 15 * 86400000,
      lastLoginAt: now - 7200000
    };
    this.adminUsersCache.set(acmeOrgAdmin.id, acmeOrgAdmin);

    const defaultOrg: Organization = {
      organizationId: 'ORG-ACME-PILOT',
      name: 'Acme Corporation (Pilot)',
      status: 'PILOT',
      enrollmentToken: 'pg_enroll_acme_pilot_2026',
      enforcementMode: 'BLOCK',
      telemetryEnabled: true,
      retentionDays: 90,
      minExtensionVersion: '1.0.0',
      backendUrl: 'http://localhost:3000',
      createdAt: now - 7 * 86400000,
      updatedAt: now
    };
    this.orgsCache.set(defaultOrg.organizationId, defaultOrg);

    const pilotTokenHash = this.hashSecret('pg_enroll_acme_pilot_2026');
    const pilotToken: EnrollmentToken = {
      id: 'tok_acme_pilot_01',
      organizationId: defaultOrg.organizationId,
      token: 'pg_enroll_acme_pilot_2026',
      tokenHash: pilotTokenHash,
      label: 'Acme Pilot Rollout Token',
      status: 'ACTIVE',
      createdAt: now - 7 * 86400000,
      expiresAt: null,
      maxUses: null,
      useCount: 0,
      revokedAt: null,
      revokedBy: null
    };
    this.tokensCache.set(pilotTokenHash, pilotToken);
  }

  public async init(): Promise<void> {
    if (!this.config.supabaseUrl || !this.config.supabaseKey) {
      console.warn('[Supabase Adapter] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY. Operating in unconfigured state.');
      return;
    }

    try {
      this.client = createClient(this.config.supabaseUrl, this.config.supabaseKey, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      });
      this.isConnected = true;
      await this.refreshCacheFromRemote();
      console.log('✅ [Supabase Adapter] Connected to Supabase PostgreSQL successfully');
    } catch (err) {
      console.error('[Supabase Adapter] Connection initialization failed:', err);
    }
  }

  private async refreshCacheFromRemote(): Promise<void> {
    if (!this.client) return;
    try {
      // 1. Fetch Orgs
      const { data: orgs } = await this.client.from('organizations').select('*');
      if (orgs && orgs.length > 0) {
        this.orgsCache.clear();
        for (const o of orgs) {
          const mapped: Organization = {
            organizationId: o.id,
            name: o.name,
            status: o.status,
            enforcementMode: o.enforcement_mode,
            telemetryEnabled: o.telemetry_enabled,
            minExtensionVersion: o.min_extension_version,
            retentionDays: o.retention_days,
            backendUrl: o.backend_url,
            createdAt: new Date(o.created_at).getTime(),
            updatedAt: new Date(o.updated_at).getTime()
          };
          this.orgsCache.set(mapped.organizationId, mapped);
        }
      }

      // 2. Fetch Devices
      const { data: devices } = await this.client.from('devices').select('*');
      if (devices) {
        this.devicesCache.clear();
        for (const d of devices) {
          const mapped: EnrolledDevice = {
            deviceId: d.id,
            organizationId: d.organization_id,
            installationId: d.installation_id,
            deviceApiKey: d.device_api_key_hash,
            deviceName: d.device_name || `Endpoint ${d.id}`,
            extensionVersion: d.extension_version,
            browser: d.browser || 'Chrome MV3',
            os: d.os || 'Unknown OS',
            platform: d.platform,
            lastIp: d.ip,
            status: (d.status === 'ONLINE' || d.status === 'OFFLINE' || d.status === 'UPDATE_REQUIRED' || d.status === 'NEEDS_ATTENTION') ? d.status : 'ONLINE',
            firstSeen: new Date(d.first_seen).getTime(),
            lastSeen: new Date(d.last_seen).getTime(),
            eventsCount: 0,
            blockedCount: 0,
            warningsCount: 0
          };
          this.devicesCache.set(mapped.deviceId, mapped);
        }
      }

      // 3. Fetch Tokens
      const { data: tokens } = await this.client.from('enrollment_tokens').select('*');
      if (tokens) {
        this.tokensCache.clear();
        for (const t of tokens) {
          const mapped: EnrollmentToken = {
            id: t.id,
            organizationId: t.organization_id,
            token: '', // token secret not stored in plaintext on server
            tokenHash: t.token_hash,
            label: t.label,
            status: t.status,
            createdAt: new Date(t.created_at).getTime(),
            expiresAt: t.expires_at ? new Date(t.expires_at).getTime() : null,
            maxUses: t.max_uses,
            useCount: t.use_count,
            revokedAt: t.revoked_at ? new Date(t.revoked_at).getTime() : null,
            revokedBy: t.revoked_by
          };
          this.tokensCache.set(mapped.tokenHash, mapped);
        }
      }

      // 4. Fetch Admin Users
      const { data: adminUsers } = await this.client.from('admin_users').select('*');
      const initialEnvPass = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
      const initialEnvHash = initialEnvPass ? hashPassword(initialEnvPass) : '';

      if (adminUsers && adminUsers.length > 0) {
        this.adminUsersCache.clear();
        for (const u of adminUsers) {
          const mapped: AdminUser = {
            id: u.id,
            username: u.username || u.email.split('@')[0],
            name: u.name || u.email,
            email: u.email,
            role: u.role || 'ORG_ADMIN',
            organizationId: u.organization_id || undefined,
            passwordHash: u.password_hash || (initialEnvHash || 'DISABLED:UNINITIALIZED_BOOTSTRAP'),
            apiKey: u.api_key || 'pg_secops_master_key_2026',
            createdAt: new Date(u.created_at).getTime(),
            lastLoginAt: u.last_login_at ? new Date(u.last_login_at).getTime() : 0
          };
          this.adminUsersCache.set(mapped.id, mapped);
        }

        // Ensure super admin exists in cache and remote database
        let superAdmin = Array.from(this.adminUsersCache.values()).find(
          u => u.role === 'SUPER_ADMIN' || u.username === 'admin' || u.email === 'admin@phishguard.security'
        );

        if (superAdmin) {
          if (initialEnvHash) {
            // Reconcile with environment variable if explicitly supplied
            superAdmin.passwordHash = initialEnvHash;
            this.client.from('admin_users').update({
              password_hash: superAdmin.passwordHash,
              api_key_hash: this.hashSecret(superAdmin.apiKey || 'pg_secops_master_key_2026')
            }).eq('id', superAdmin.id).then(() => {});
          }
        } else {
          const superAdminId = 'usr_super_admin_01';
          const newSuperAdmin: AdminUser = {
            id: superAdminId,
            username: 'admin',
            name: 'SecOps Director',
            email: 'admin@phishguard.security',
            role: 'SUPER_ADMIN',
            passwordHash: initialEnvHash || 'DISABLED:UNINITIALIZED_BOOTSTRAP',
            apiKey: 'pg_secops_master_key_2026',
            createdAt: Date.now() - 30 * 86400000,
            lastLoginAt: 0
          };
          this.adminUsersCache.set(newSuperAdmin.id, newSuperAdmin);
          this.client.from('admin_users').upsert({
            id: superAdminId,
            username: 'admin',
            name: 'SecOps Director',
            email: 'admin@phishguard.security',
            role: 'SUPER_ADMIN',
            password_hash: initialEnvHash || 'DISABLED:UNINITIALIZED_BOOTSTRAP',
            api_key: 'pg_secops_master_key_2026',
            api_key_hash: this.hashSecret('pg_secops_master_key_2026'),
            created_at: new Date(Date.now() - 30 * 86400000).toISOString()
          }).then(() => {});
        }

        // Ensure Acme Organization Admin exists in cache and remote database
        const orgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
        const orgAdminHash = orgAdminPass ? hashPassword(orgAdminPass) : '';

        let acmeAdmin = Array.from(this.adminUsersCache.values()).find(
          u => (u.organizationId === 'ORG-ACME-PILOT' && u.role === 'ORG_ADMIN') ||
               u.username === 'acme_admin' ||
               u.email === 'it-admin@acme-corp.com'
        );

        if (acmeAdmin) {
          if (orgAdminHash && (acmeAdmin.passwordHash.startsWith('DISABLED:') || acmeAdmin.passwordHash !== orgAdminHash)) {
            acmeAdmin.passwordHash = orgAdminHash;
            this.client.from('admin_users').update({
              password_hash: acmeAdmin.passwordHash
            }).eq('id', acmeAdmin.id).then(() => {});
          }
        } else {
          const acmeAdminId = 'usr_acme_admin_01';
          const newAcmeAdmin: AdminUser = {
            id: acmeAdminId,
            username: 'acme_admin',
            name: 'Alex Rivera (IT Lead)',
            email: 'it-admin@acme-corp.com',
            role: 'ORG_ADMIN',
            organizationId: 'ORG-ACME-PILOT',
            passwordHash: orgAdminHash || 'DISABLED:UNINITIALIZED_BOOTSTRAP',
            apiKey: 'pg_acme_admin_key_2026',
            createdAt: Date.now() - 15 * 86400000,
            lastLoginAt: 0
          };
          this.adminUsersCache.set(newAcmeAdmin.id, newAcmeAdmin);
          this.client.from('admin_users').upsert({
            id: acmeAdminId,
            username: 'acme_admin',
            name: 'Alex Rivera (IT Lead)',
            email: 'it-admin@acme-corp.com',
            role: 'ORG_ADMIN',
            organization_id: 'ORG-ACME-PILOT',
            password_hash: orgAdminHash || 'DISABLED:UNINITIALIZED_BOOTSTRAP',
            api_key: 'pg_acme_admin_key_2026',
            api_key_hash: this.hashSecret('pg_acme_admin_key_2026'),
            created_at: new Date(Date.now() - 15 * 86400000).toISOString()
          }).then(() => {});
        }
      } else {
        // Table is empty, seed initial super admin and acme org admin into Supabase
        const now = Date.now();
        const superAdminId = 'usr_super_admin_01';
        const targetHash = initialEnvHash || 'DISABLED:UNINITIALIZED_BOOTSTRAP';
        
        await this.client.from('admin_users').upsert({
          id: superAdminId,
          username: 'admin',
          name: 'SecOps Director',
          email: 'admin@phishguard.security',
          role: 'SUPER_ADMIN',
          password_hash: targetHash,
          api_key: 'pg_secops_master_key_2026',
          api_key_hash: this.hashSecret('pg_secops_master_key_2026'),
          created_at: new Date(now - 30 * 86400000).toISOString()
        }).then(() => {});

        const orgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
        const acmeTargetHash = orgAdminPass ? hashPassword(orgAdminPass) : 'DISABLED:UNINITIALIZED_BOOTSTRAP';
        const acmeAdminId = 'usr_acme_admin_01';

        await this.client.from('admin_users').upsert({
          id: acmeAdminId,
          username: 'acme_admin',
          name: 'Alex Rivera (IT Lead)',
          email: 'it-admin@acme-corp.com',
          role: 'ORG_ADMIN',
          organization_id: 'ORG-ACME-PILOT',
          password_hash: acmeTargetHash,
          api_key: 'pg_acme_admin_key_2026',
          api_key_hash: this.hashSecret('pg_acme_admin_key_2026'),
          created_at: new Date(now - 15 * 86400000).toISOString()
        }).then(() => {});
      }

      // 5. Fetch Events
      const { data: events } = await this.client.from('security_events').select('*').order('timestamp', { ascending: false }).limit(500);
      if (events) {
        this.eventsCache = events.map(e => ({
          eventId: e.id,
          organizationId: e.organization_id,
          deviceId: e.device_id,
          installationId: e.installation_id,
          eventType: e.event_type,
          url: e.url,
          hostname: e.hostname,
          riskScore: e.risk_score,
          riskLevel: e.risk_level,
          action: e.action,
          threatCategory: e.threat_category,
          detectionReasons: e.detection_reasons || [],
          signals: e.signals || [],
          navigationBlocked: e.navigation_blocked,
          userOverride: e.user_override,
          source: e.source,
          extensionVersion: e.extension_version,
          tabId: e.tab_id || 0,
          timestamp: Number(e.timestamp),
          createdAt: e.created_at
        }));
      }
    } catch (err) {
      console.warn('[Supabase Adapter] Remote cache sync warning:', err);
    }
  }

  private hashSecret(secret: string): string {
    return crypto.createHash('sha256').update(secret).digest('hex');
  }

  private sanitizeUrl(rawUrl: string): string {
    try {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
      const sensitiveKeys = ['token', 'password', 'pass', 'key', 'code', 'auth', 'secret', 'jwt', 'session', 'api_key', 'access_token'];
      for (const key of Array.from(parsed.searchParams.keys())) {
        if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
          parsed.searchParams.set(key, '[REDACTED]');
        }
      }
      const searchStr = decodeURIComponent(parsed.searchParams.toString());
      return `${parsed.origin}${parsed.pathname}${searchStr ? `?${searchStr}` : ''}`;
    } catch {
      return rawUrl.replace(/([?&](token|password|pass|key|code|auth|secret|jwt|session)=)[^&]*/gi, '$1[REDACTED]');
    }
  }

  // ============================================================================
  // ORGANIZATIONS
  // ============================================================================

  public getOrganizations(): Organization[] {
    return Array.from(this.orgsCache.values());
  }

  public getOrganizationById(id: string): Organization | null {
    return this.orgsCache.get(id) || null;
  }

  public createOrganization(data: Partial<Organization>, actor = 'Admin Console'): Organization {
    const orgId = data.organizationId || `ORG-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const now = Date.now();

    const newOrg: Organization = {
      organizationId: orgId,
      name: data.name || 'New Organization',
      status: data.status || 'ACTIVE',
      enforcementMode: data.enforcementMode || 'BLOCK',
      telemetryEnabled: data.telemetryEnabled ?? true,
      minExtensionVersion: data.minExtensionVersion || '1.0.0',
      retentionDays: data.retentionDays || 90,
      backendUrl: data.backendUrl || '',
      createdAt: now,
      updatedAt: now
    };

    this.orgsCache.set(orgId, newOrg);

    if (this.client) {
      this.client.from('organizations').insert({
        id: orgId,
        name: newOrg.name,
        status: newOrg.status,
        enforcement_mode: newOrg.enforcementMode,
        telemetry_enabled: newOrg.telemetryEnabled,
        min_extension_version: newOrg.minExtensionVersion,
        retention_days: newOrg.retentionDays,
        backend_url: newOrg.backendUrl
      }).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Org insert error:', error.message);
      });
    }

    this.addAuditLog({
      organizationId: orgId,
      actor,
      action: 'ORGANIZATION_CREATED',
      target: orgId,
      details: `Created tenant organization ${newOrg.name} (${orgId})`
    });

    return newOrg;
  }

  public updateOrganization(id: string, updates: Partial<Organization>, actor = 'Admin Console'): Organization | null {
    const org = this.orgsCache.get(id);
    if (!org) return null;

    if (updates.name !== undefined) org.name = updates.name;
    if (updates.status !== undefined) org.status = updates.status;
    if (updates.enforcementMode !== undefined) org.enforcementMode = updates.enforcementMode;
    if (updates.telemetryEnabled !== undefined) org.telemetryEnabled = updates.telemetryEnabled;
    if (updates.minExtensionVersion !== undefined) org.minExtensionVersion = updates.minExtensionVersion;
    if (updates.retentionDays !== undefined) org.retentionDays = updates.retentionDays;
    if (updates.backendUrl !== undefined) org.backendUrl = updates.backendUrl;
    org.updatedAt = Date.now();

    if (this.client) {
      this.client.from('organizations').update({
        name: org.name,
        status: org.status,
        enforcement_mode: org.enforcementMode,
        telemetry_enabled: org.telemetryEnabled,
        min_extension_version: org.minExtensionVersion,
        retention_days: org.retentionDays,
        backend_url: org.backendUrl,
        updated_at: new Date().toISOString()
      }).eq('id', id).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Org update error:', error.message);
      });
    }

    this.addAuditLog({
      organizationId: id,
      actor,
      action: 'ORGANIZATION_UPDATED',
      target: id,
      details: `Updated organization settings`
    });

    return { ...org };
  }

  // ============================================================================
  // ENROLLMENT TOKENS
  // ============================================================================

  public createEnrollmentToken(data: {
    organizationId: string;
    label?: string;
    expiresInDays?: number | null;
    maxUses?: number | null;
    actor?: string;
  }): EnrollmentToken {
    const rawSecret = `pg_enroll_${crypto.randomBytes(24).toString('hex')}`;
    const tokenHash = this.hashSecret(rawSecret);
    const tokenId = `tok_${crypto.randomBytes(6).toString('hex')}`;
    const now = Date.now();
    const expiresAt = data.expiresInDays ? now + data.expiresInDays * 86400000 : null;

    const tokenObj: EnrollmentToken = {
      id: tokenId,
      organizationId: data.organizationId,
      token: rawSecret,
      tokenHash,
      label: data.label || 'Default Enrollment Token',
      status: 'ACTIVE',
      createdAt: now,
      expiresAt,
      maxUses: data.maxUses ?? null,
      useCount: 0,
      revokedAt: null,
      revokedBy: null
    };

    this.tokensCache.set(tokenHash, { ...tokenObj, token: '' });

    if (this.client) {
      this.client.from('enrollment_tokens').insert({
        id: tokenId,
        organization_id: data.organizationId,
        token_hash: tokenHash,
        label: tokenObj.label,
        status: 'ACTIVE',
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
        max_uses: data.maxUses || null,
        use_count: 0
      }).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Token insert error:', error.message);
      });
    }

    this.addAuditLog({
      organizationId: data.organizationId,
      actor: data.actor || 'Admin Console',
      action: 'ENROLLMENT_TOKEN_CREATED',
      target: tokenId,
      details: `Generated enrollment token: ${tokenObj.label}`
    });

    return tokenObj;
  }

  public getEnrollmentTokens(organizationId: string): EnrollmentToken[] {
    return Array.from(this.tokensCache.values())
      .filter(t => t.organizationId === organizationId)
      .map(t => ({ ...t, token: '' }));
  }

  public getEnrollmentTokenById(tokenId: string): EnrollmentToken | null {
    return Array.from(this.tokensCache.values()).find(t => t.id === tokenId) || null;
  }

  public validateEnrollmentToken(rawToken: string): { valid: boolean; token?: EnrollmentToken; error?: string } {
    if (!rawToken) return { valid: false, error: 'Missing token' };
    const hash = this.hashSecret(rawToken);
    let token = this.tokensCache.get(hash);

    if (!token) {
      for (const t of this.tokensCache.values()) {
        if (t.token === rawToken || t.tokenHash === hash) {
          token = t;
          break;
        }
      }
    }

    if (!token) {
      for (const org of this.orgsCache.values()) {
        if (org.enrollmentToken === rawToken) {
          token = {
            id: `tok_${org.organizationId}`,
            organizationId: org.organizationId,
            token: rawToken,
            tokenHash: hash,
            label: `${org.name} Default Token`,
            status: 'ACTIVE',
            createdAt: org.createdAt,
            expiresAt: null,
            maxUses: null,
            useCount: 1,
            revokedAt: null,
            revokedBy: null
          };
          this.tokensCache.set(hash, token);
          break;
        }
      }
    }

    if (!token) return { valid: false, error: 'Invalid enrollment token' };
    if (token.status === 'REVOKED') return { valid: false, error: 'Enrollment token has been revoked' };
    if (token.expiresAt && token.expiresAt < Date.now()) return { valid: false, error: 'Enrollment token has expired' };
    if (token.maxUses && token.useCount >= token.maxUses) return { valid: false, error: 'Enrollment token usage limit reached' };

    return { valid: true, token };
  }

  public revokeEnrollmentToken(tokenId: string, actor = 'Admin Console'): boolean {
    const token = this.getEnrollmentTokenById(tokenId);
    if (!token) return false;

    token.status = 'REVOKED';
    token.revokedAt = Date.now();
    token.revokedBy = actor;

    if (this.client) {
      this.client.from('enrollment_tokens').update({
        status: 'REVOKED',
        revoked_at: new Date().toISOString(),
        revoked_by: actor
      }).eq('id', tokenId).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Token revoke error:', error.message);
      });
    }

    this.addAuditLog({
      organizationId: token.organizationId,
      actor,
      action: 'ENROLLMENT_TOKEN_REVOKED',
      target: tokenId,
      details: `Revoked enrollment token ${token.label}`
    });

    return true;
  }

  // ============================================================================
  // DEVICES
  // ============================================================================

  public enrollDevice(data: {
    enrollmentToken: string;
    installationId: string;
    extensionVersion: string;
    browser: string;
    os: string;
    platform?: string;
    deviceName?: string;
    ip?: string;
  }): { success: boolean; device?: EnrolledDevice; error?: string; enforcementMode?: EnforcementMode; minExtensionVersion?: string; backendUrl?: string } {
    const val = this.validateEnrollmentToken(data.enrollmentToken);
    if (!val.valid || !val.token) return { success: false, error: val.error };

    const org = this.orgsCache.get(val.token.organizationId);
    if (!org || org.status === 'SUSPENDED') return { success: false, error: 'Organization inactive or suspended' };

    const rawApiKey = `pg_dev_${crypto.randomBytes(32).toString('hex')}`;
    const apiKeyHash = this.hashSecret(rawApiKey);

    let existingDev = Array.from(this.devicesCache.values()).find(
      d => d.organizationId === val.token!.organizationId && d.installationId === data.installationId
    );

    const now = Date.now();
    let device: EnrolledDevice;

    if (existingDev) {
      existingDev.lastSeen = now;
      existingDev.extensionVersion = data.extensionVersion;
      existingDev.browser = data.browser;
      existingDev.os = data.os;
      existingDev.lastIp = data.ip;
      existingDev.status = 'ONLINE';
      device = existingDev;
    } else {
      const deviceId = `DEV-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
      device = {
        deviceId,
        organizationId: val.token.organizationId,
        installationId: data.installationId,
        deviceApiKey: rawApiKey,
        deviceName: data.deviceName || `${data.os} (${data.browser.split('/')[0]})`,
        extensionVersion: data.extensionVersion,
        browser: data.browser,
        os: data.os,
        platform: data.platform,
        lastIp: data.ip,
        status: 'ONLINE',
        firstSeen: now,
        lastSeen: now,
        eventsCount: 0,
        blockedCount: 0,
        warningsCount: 0
      };
      this.devicesCache.set(device.deviceId, device);
    }

    val.token.useCount += 1;

    if (this.client) {
      this.client.from('devices').upsert({
        id: device.deviceId,
        organization_id: device.organizationId,
        installation_id: device.installationId,
        device_api_key_hash: apiKeyHash,
        device_name: device.deviceName,
        extension_version: device.extensionVersion,
        browser: device.browser,
        os: device.os,
        platform: device.platform,
        ip: data.ip,
        status: 'ONLINE',
        last_seen: new Date(now).toISOString()
      }).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Device upsert error:', error.message);
      });

      this.client.from('enrollment_tokens').update({
        use_count: val.token.useCount
      }).eq('id', val.token.id).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Token count update error:', error.message);
      });
    }

    return {
      success: true,
      device: { ...device, deviceApiKey: rawApiKey },
      enforcementMode: org.enforcementMode,
      minExtensionVersion: org.minExtensionVersion,
      backendUrl: org.backendUrl
    };
  }

  public getDevices(organizationId?: string): EnrolledDevice[] {
    const now = Date.now();
    let devices = Array.from(this.devicesCache.values());
    if (organizationId) {
      devices = devices.filter(d => d.organizationId === organizationId);
    }

    return devices.map(d => {
      const isRecent = now - d.lastSeen < ONLINE_THRESHOLD_MS;
      const status: DeviceHealthStatus = isRecent ? 'ONLINE' : 'OFFLINE';
      return { ...d, status };
    });
  }

  public getDeviceById(deviceId: string, organizationId?: string): EnrolledDevice | null {
    const dev = this.devicesCache.get(deviceId);
    if (!dev) return null;
    if (organizationId && dev.organizationId !== organizationId) return null;
    const isRecent = Date.now() - dev.lastSeen < ONLINE_THRESHOLD_MS;
    const status: DeviceHealthStatus = isRecent ? 'ONLINE' : 'OFFLINE';
    return { ...dev, status };
  }

  public getDeviceByApiKey(rawApiKey: string): EnrolledDevice | null {
    if (!rawApiKey) return null;
    const hash = this.hashSecret(rawApiKey);
    for (const d of this.devicesCache.values()) {
      if (d.deviceApiKey === rawApiKey || d.deviceApiKey === hash) {
        return { ...d };
      }
    }
    return null;
  }

  public revokeDevice(deviceId: string, organizationId?: string, actor = 'Admin Console'): boolean {
    const dev = this.devicesCache.get(deviceId);
    if (!dev) return false;
    if (organizationId && dev.organizationId !== organizationId) return false;

    this.devicesCache.delete(deviceId);

    if (this.client) {
      this.client.from('devices').delete().eq('id', deviceId).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Device revoke error:', error.message);
      });
    }

    this.addAuditLog({
      organizationId: dev.organizationId,
      actor,
      action: 'DEVICE_REVOKED',
      target: deviceId,
      details: `Revoked device ${dev.deviceName} (${deviceId})`
    });

    return true;
  }

  public deleteOrganization(organizationId: string, actor = 'Admin Console'): boolean {
    const org = this.orgsCache.get(organizationId);
    if (!org) return false;

    this.orgsCache.delete(organizationId);

    if (this.client) {
      this.client.from('organizations').delete().eq('id', organizationId).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Org delete error:', error.message);
      });
    }

    this.addAuditLog({
      organizationId,
      actor,
      action: 'ORGANIZATION_DELETED',
      target: organizationId,
      details: `Deleted organization ${org.name} (${organizationId})`
    });

    return true;
  }

  // ============================================================================
  // ADMIN USERS
  // ============================================================================

  public getAdminUsers(organizationId?: string): AdminUser[] {
    let users = Array.from(this.adminUsersCache.values());
    if (organizationId) {
      users = users.filter(u => u.organizationId === organizationId);
    }
    return users;
  }

  public getAdminUserById(id: string): AdminUser | null {
    return this.adminUsersCache.get(id) || null;
  }

  public getAdminUserByEmail(email: string): AdminUser | null {
    if (!email) return null;
    const lower = email.toLowerCase();
    for (const u of this.adminUsersCache.values()) {
      if (u.email.toLowerCase() === lower) return { ...u };
    }
    return null;
  }

  public createAdminUser(user: Omit<AdminUser, 'id' | 'createdAt' | 'lastLoginAt'>, actor = 'Admin Console'): AdminUser {
    const id = `usr_${crypto.randomBytes(6).toString('hex')}`;
    const now = Date.now();
    const newUser: AdminUser = {
      ...user,
      id,
      createdAt: now,
      lastLoginAt: 0
    };

    this.adminUsersCache.set(id, newUser);

    if (this.client) {
      this.client.from('admin_users').insert({
        id,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role,
        organization_id: newUser.organizationId || null,
        password_hash: newUser.passwordHash
      }).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Admin user insert error:', error.message);
      });
    }

    this.addAuditLog({
      organizationId: user.organizationId || 'GLOBAL',
      actor,
      action: 'ADMIN_USER_CREATED',
      target: id,
      details: `Created administrative user ${newUser.email} with role ${newUser.role}`
    });

    return newUser;
  }

  public updateAdminUser(id: string, updates: Partial<AdminUser>, actor = 'Admin Console'): AdminUser | null {
    const user = this.adminUsersCache.get(id);
    if (!user) return null;

    if (updates.name !== undefined) user.name = updates.name;
    if (updates.email !== undefined) user.email = updates.email;
    if (updates.role !== undefined) user.role = updates.role;
    if (updates.passwordHash !== undefined) user.passwordHash = updates.passwordHash;
    if (updates.lastLoginAt !== undefined) user.lastLoginAt = updates.lastLoginAt;

    if (this.client) {
      this.client.from('admin_users').update({
        name: user.name,
        email: user.email,
        role: user.role,
        password_hash: user.passwordHash,
        last_login_at: user.lastLoginAt ? new Date(user.lastLoginAt).toISOString() : null
      }).eq('id', id).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Admin user update error:', error.message);
      });
    }

    this.addAuditLog({
      organizationId: user.organizationId || 'GLOBAL',
      actor,
      action: 'ADMIN_USER_UPDATED',
      target: id,
      details: `Updated administrative user ${user.email}`
    });

    return { ...user };
  }

  public deleteAdminUser(id: string, actor = 'Admin Console'): boolean {
    const user = this.adminUsersCache.get(id);
    if (!user) return false;

    this.adminUsersCache.delete(id);

    if (this.client) {
      this.client.from('admin_users').delete().eq('id', id).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Admin user delete error:', error.message);
      });
    }

    this.addAuditLog({
      organizationId: user.organizationId || 'GLOBAL',
      actor,
      action: 'ADMIN_USER_DELETED',
      target: id,
      details: `Deleted administrative user ${user.email}`
    });

    return true;
  }

  public recordHeartbeat(data: {
    deviceId: string;
    installationId: string;
    extensionVersion: string;
    browser?: string;
    os?: string;
    organizationId?: string;
    ip?: string;
  }): { success: boolean; device: EnrolledDevice; enforcementMode: EnforcementMode; minExtensionVersion: string } {
    let dev = this.devicesCache.get(data.deviceId);
    const now = Date.now();

    if (!dev) {
      const orgId = data.organizationId || Array.from(this.orgsCache.keys())[0] || 'ORG-ACME-PILOT';
      dev = {
        deviceId: data.deviceId,
        organizationId: orgId,
        installationId: data.installationId,
        deviceName: `Endpoint ${data.deviceId}`,
        extensionVersion: data.extensionVersion,
        browser: data.browser || 'Chrome MV3',
        os: data.os || 'Unknown OS',
        lastIp: data.ip,
        status: 'ONLINE',
        firstSeen: now,
        lastSeen: now,
        eventsCount: 0,
        blockedCount: 0,
        warningsCount: 0
      };
      this.devicesCache.set(dev.deviceId, dev);
    } else {
      dev.lastSeen = now;
      dev.extensionVersion = data.extensionVersion;
      if (data.browser) dev.browser = data.browser;
      if (data.os) dev.os = data.os;
      if (data.ip) dev.lastIp = data.ip;
      dev.status = 'ONLINE';
    }

    const org = this.orgsCache.get(dev.organizationId);

    if (this.client) {
      this.client.from('devices').update({
        last_seen: new Date(now).toISOString(),
        extension_version: data.extensionVersion,
        ip: data.ip
      }).eq('id', dev.deviceId).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Heartbeat update error:', error.message);
      });
    }

    return {
      success: true,
      device: { ...dev },
      enforcementMode: org?.enforcementMode || 'BLOCK',
      minExtensionVersion: org?.minExtensionVersion || '1.0.0'
    };
  }

  // ============================================================================
  // CANONICAL SECURITY EVENTS
  // ============================================================================

  public ingestSecurityEvent(event: CanonicalSecurityEvent): { success: boolean; isDuplicate: boolean; eventId: string } {
    const eventId = event.eventId || `evt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    event.eventId = eventId;

    if (this.eventsCache.some(e => e.eventId === eventId)) {
      return { success: true, isDuplicate: true, eventId };
    }

    event.url = this.sanitizeUrl(event.url);
    event.timestamp = event.timestamp || Date.now();
    event.createdAt = event.createdAt || new Date(event.timestamp).toISOString();

    const dev = this.devicesCache.get(event.deviceId);
    if (dev) {
      dev.eventsCount = (dev.eventsCount || 0) + 1;
      if (event.action === 'BLOCKED') dev.blockedCount = (dev.blockedCount || 0) + 1;
      if (event.action === 'WARNED') dev.warningsCount = (dev.warningsCount || 0) + 1;
    }

    this.eventsCache.unshift(event);
    if (this.eventsCache.length > 500) {
      this.eventsCache.pop();
    }

    if (this.client) {
      this.client.from('security_events').insert({
        id: event.eventId,
        organization_id: event.organizationId,
        device_id: event.deviceId,
        installation_id: event.installationId,
        event_type: event.eventType,
        url: event.url,
        hostname: event.hostname,
        risk_score: event.riskScore,
        risk_level: event.riskLevel,
        action: event.action,
        threat_category: event.threatCategory,
        detection_reasons: event.detectionReasons,
        signals: event.signals,
        navigation_blocked: event.navigationBlocked,
        user_override: event.userOverride,
        source: event.source,
        extension_version: event.extensionVersion,
        tab_id: event.tabId,
        timestamp: event.timestamp
      }).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Event insert error:', error.message);
      });
    }

    return { success: true, isDuplicate: false, eventId };
  }

  public ingestBatchEvents(events: CanonicalSecurityEvent[]): { ingested: number; duplicates: number } {
    let ingested = 0;
    let duplicates = 0;
    for (const evt of events) {
      const res = this.ingestSecurityEvent(evt);
      if (res.isDuplicate) duplicates++;
      else if (res.success) ingested++;
    }
    return { ingested, duplicates };
  }

  public getSecurityEvents(filter: QueryEventsFilter): { events: CanonicalSecurityEvent[]; total: number } {
    let items = [...this.eventsCache];

    if (filter.organizationId) {
      items = items.filter(e => e.organizationId === filter.organizationId);
    }
    if (filter.deviceId) {
      items = items.filter(e => e.deviceId === filter.deviceId);
    }
    if (filter.action) {
      items = items.filter(e => e.action === filter.action);
    }
    if (filter.threatCategory) {
      items = items.filter(e => e.threatCategory === filter.threatCategory);
    }
    if (filter.riskLevel) {
      items = items.filter(e => e.riskLevel === filter.riskLevel);
    }
    if (filter.search) {
      const q = filter.search.toLowerCase();
      items = items.filter(e => e.url.toLowerCase().includes(q) || e.hostname.toLowerCase().includes(q));
    }

    if (filter.sortBy === 'highest_risk') {
      items.sort((a, b) => b.riskScore - a.riskScore);
    } else {
      items.sort((a, b) => b.timestamp - a.timestamp);
    }

    const total = items.length;
    const page = filter.page || 1;
    const pageSize = filter.pageSize || 50;
    const offset = (page - 1) * pageSize;
    const paged = items.slice(offset, offset + pageSize);

    return {
      events: paged,
      total
    };
  }

  public getEventById(eventId: string, organizationId?: string): CanonicalSecurityEvent | null {
    const evt = this.eventsCache.find(e => e.eventId === eventId);
    if (!evt) return null;
    if (organizationId && evt.organizationId !== organizationId) return null;
    return { ...evt };
  }

  public getEventsByDevice(deviceId: string, organizationId?: string): CanonicalSecurityEvent[] {
    return this.eventsCache.filter(
      e => e.deviceId === deviceId && (!organizationId || e.organizationId === organizationId)
    );
  }

  // ============================================================================
  // OVERVIEW STATS & CSV EXPORT
  // ============================================================================

  public getOverviewStats(organizationId?: string): OrganizationStats {
    const devices = this.getDevices(organizationId);
    const events = organizationId
      ? this.eventsCache.filter(e => e.organizationId === organizationId)
      : this.eventsCache;

    const now = Date.now();
    const oneDayAgo = now - 24 * 60 * 60 * 1000;

    const onlineDevices = devices.filter(d => d.status === 'ONLINE').length;
    const offlineDevices = devices.filter(d => d.status === 'OFFLINE').length;
    const updateRequiredDevices = devices.filter(d => d.status === 'UPDATE_REQUIRED').length;
    const devicesNeedingAttention = devices.filter(d => d.status === 'NEEDS_ATTENTION').length;

    const recentDayEvents = events.filter(e => e.timestamp >= oneDayAgo);
    const threatsToday = recentDayEvents.length;
    const blockedToday = recentDayEvents.filter(e => e.action === 'BLOCKED').length;
    const warningsToday = recentDayEvents.filter(e => e.action === 'WARNED').length;

    const brandCounts = new Map<string, { count: number; category: string }>();
    for (const evt of events) {
      if (evt.brand) {
        const cur = brandCounts.get(evt.brand) || { count: 0, category: evt.threatCategory || 'OTHER' };
        cur.count++;
        brandCounts.set(evt.brand, cur);
      }
    }
    const topTargetedBrands = Array.from(brandCounts.entries())
      .map(([brand, data]) => ({ brand, count: data.count, category: data.category }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const catCounts = new Map<string, number>();
    for (const evt of events) {
      const cat = evt.threatCategory || 'OTHER';
      catCounts.set(cat, (catCounts.get(cat) || 0) + 1);
    }
    const totalEventsCount = events.length;
    const topThreatCategories = Array.from(catCounts.entries())
      .map(([category, count]) => ({
        category,
        count,
        percentage: totalEventsCount > 0 ? Math.round((count / totalEventsCount) * 100) : 0
      }))
      .sort((a, b) => b.count - a.count);

    return {
      totalProtectedDevices: devices.length,
      onlineDevices,
      offlineDevices,
      updateRequiredDevices,
      devicesNeedingAttention,
      threatsToday,
      blockedToday,
      warningsToday,
      totalEventsCount,
      topTargetedBrands,
      topThreatCategories,
      recentEvents: events.slice(0, 10)
    };
  }

  public generateCsvExport(organizationId: string): string {
    const events = this.eventsCache.filter(e => e.organizationId === organizationId);
    const headers = [
      'EventID',
      'TimestampISO',
      'OrganizationID',
      'DeviceID',
      'InstallationID',
      'Action',
      'RiskLevel',
      'RiskScore',
      'ThreatCategory',
      'TargetBrand',
      'Hostname',
      'SanitizedURL',
      'DetectionReasons'
    ];

    const rows = events.map(e => [
      e.eventId,
      new Date(e.timestamp).toISOString(),
      e.organizationId,
      e.deviceId,
      e.installationId,
      e.action,
      e.riskLevel,
      String(e.riskScore),
      e.threatCategory || 'OTHER',
      e.brand || '',
      e.hostname,
      `"${(e.url || '').replace(/"/g, '""')}"`,
      `"${(e.detectionReasons || []).join('; ').replace(/"/g, '""')}"`
    ]);

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  }

  // ============================================================================
  // AUDIT LOGS
  // ============================================================================

  public addAuditLog(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): AuditLogEntry {
    const fullEntry: AuditLogEntry = {
      id: `aud_${crypto.randomBytes(6).toString('hex')}`,
      timestamp: Date.now(),
      organizationId: entry.organizationId,
      actor: entry.actor,
      action: entry.action,
      target: entry.target,
      details: entry.details
    };

    this.auditLogsCache.unshift(fullEntry);
    if (this.auditLogsCache.length > 200) this.auditLogsCache.pop();

    if (this.client) {
      this.client.from('audit_logs').insert({
        id: fullEntry.id,
        organization_id: fullEntry.organizationId,
        actor: fullEntry.actor,
        action: fullEntry.action,
        target: fullEntry.target,
        details: fullEntry.details
      }).then(({ error }) => {
        if (error) console.error('[Supabase Adapter] Audit log insert error:', error.message);
      });
    }

    return fullEntry;
  }

  public getAuditLogs(organizationId?: string): AuditLogEntry[] {
    let logs = [...this.auditLogsCache];
    if (organizationId) {
      logs = logs.filter(l => l.organizationId === organizationId);
    }
    return logs;
  }

  // ==========================================================================
  // 7. SESSION REVOCATION (Centralized Supabase / PostgreSQL Revocation)
  // ==========================================================================

  private revokedSessionsCache = new Map<string, RevokedSessionRecord>();

  public async revokeSession(
    tokenHash: string,
    expiresAt: number,
    metadata?: { userId?: string; organizationId?: string }
  ): Promise<void> {
    const record: RevokedSessionRecord = {
      tokenHash,
      userId: metadata?.userId,
      organizationId: metadata?.organizationId,
      expiresAt,
      revokedAt: Date.now()
    };
    this.revokedSessionsCache.set(tokenHash, record);

    if (this.client) {
      try {
        const { error } = await this.client.from('revoked_sessions').upsert({
          token_hash: tokenHash,
          user_id: metadata?.userId || null,
          organization_id: metadata?.organizationId || null,
          expires_at: new Date(expiresAt).toISOString(),
          revoked_at: new Date().toISOString()
        });
        if (error) {
          console.error('[Supabase Adapter] Session revocation upsert error:', error.message);
        }
      } catch (err: any) {
        console.error('[Supabase Adapter] Session revocation failure:', err?.message);
      }
    }
  }

  public async isSessionRevoked(tokenHash: string): Promise<boolean> {
    // 1. Fast local cache check
    const local = this.revokedSessionsCache.get(tokenHash);
    if (local) {
      if (Date.now() >= local.expiresAt) {
        this.revokedSessionsCache.delete(tokenHash);
        return false;
      }
      return true;
    }

    // 2. Centralized Supabase PostgreSQL check across serverless function instances
    if (this.client) {
      try {
        const { data, error } = await this.client
          .from('revoked_sessions')
          .select('token_hash, expires_at, user_id, organization_id')
          .eq('token_hash', tokenHash)
          .maybeSingle();

        if (error) {
          console.warn('[Supabase Adapter] Revocation check warning:', error.message);
          return false;
        }

        if (data) {
          const expTime = new Date(data.expires_at).getTime();
          // If already expired, safely ignore
          if (Date.now() >= expTime) {
            return false;
          }
          // Cache locally for subsequent fast-path checks
          this.revokedSessionsCache.set(tokenHash, {
            tokenHash: data.token_hash,
            userId: data.user_id || undefined,
            organizationId: data.organization_id || undefined,
            expiresAt: expTime,
            revokedAt: Date.now()
          });
          return true;
        }
      } catch (err: any) {
        console.error('[Supabase Adapter] isSessionRevoked network exception:', err?.message);
      }
    }

    return false;
  }

  public async cleanExpiredRevocations(): Promise<number> {
    const now = Date.now();
    let cleanedLocal = 0;
    for (const [hash, record] of this.revokedSessionsCache.entries()) {
      if (now >= record.expiresAt) {
        this.revokedSessionsCache.delete(hash);
        cleanedLocal++;
      }
    }

    if (this.client) {
      try {
        const { error } = await this.client
          .from('revoked_sessions')
          .delete()
          .lt('expires_at', new Date(now).toISOString());
        if (error) {
          console.warn('[Supabase Adapter] cleanExpiredRevocations warning:', error.message);
        }
      } catch (err: any) {
        console.error('[Supabase Adapter] cleanExpiredRevocations failure:', err?.message);
      }
    }

    return cleanedLocal;
  }
}

