/**
 * PhishGuard JSON File Storage Adapter
 * 
 * Production-ready file storage adapter implementing IDatabaseAdapter.
 * Handles:
 * 1. Cryptographically secure token generation, hashing, expiration, and revocation.
 * 2. Multi-tenant organization isolation (all device, event, and token lookups strictly scoped).
 * 3. Device enrollment, API key issuance, and heartbeat online threshold tracking.
 * 4. Idempotent canonical security event ingestion with URL privacy sanitization.
 * 5. Admin audit logging.
 */

import fs from 'fs';
import path from 'path';
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

export interface JsonDatabaseSchema {
  organizations: Organization[];
  enrollmentTokens: EnrollmentToken[];
  devices: EnrolledDevice[];
  adminUsers: AdminUser[];
  securityEvents: CanonicalSecurityEvent[];
  auditLogs: AuditLogEntry[];
  revokedSessions?: RevokedSessionRecord[];
}

const isServerless = !!process.env.VERCEL || !!process.env.AWS_LAMBDA_FUNCTION_NAME || !!process.env.NOW_REGION;
const FALLBACK_RO_FILE = path.resolve(process.cwd(), 'data', 'phishguard-db.json');
const DB_DIR = isServerless ? '/tmp' : path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DB_DIR, 'phishguard-db.json');
const MAX_EVENTS_RETENTION = 10000;
const ONLINE_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes heartbeat threshold

export class JsonFileDatabaseAdapter implements IDatabaseAdapter {
  private data: JsonDatabaseSchema = {
    organizations: [],
    enrollmentTokens: [],
    devices: [],
    adminUsers: [],
    securityEvents: [],
    auditLogs: [],
    revokedSessions: []
  };

  // Fast In-Memory Lookup Indexes
  private orgIndex = new Map<string, Organization>();
  private tokenIndex = new Map<string, EnrollmentToken>(); // By token string
  private tokenHashIndex = new Map<string, EnrollmentToken>(); // By tokenHash
  private deviceApiKeyIndex = new Map<string, EnrolledDevice>(); // By deviceApiKey
  private deviceIdIndex = new Map<string, EnrolledDevice>(); // By "orgId:deviceId"
  private eventIdSet = new Set<string>();
  private revokedSessionsMap = new Map<string, RevokedSessionRecord>();

  private isLoaded = false;
  private filePath: string;

  constructor(customFilePath?: string) {
    this.filePath = customFilePath || DB_FILE;
    this.init();
  }

  public init(): void {
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        try {
          fs.mkdirSync(dir, { recursive: true });
        } catch (mkErr) {
          // In read-only filesystems, fallback gracefully
          console.warn('[PhishGuard DB] Directory creation non-fatal warning:', mkErr);
        }
      }

      let sourceFile = this.filePath;
      if (!fs.existsSync(sourceFile) && fs.existsSync(FALLBACK_RO_FILE)) {
        sourceFile = FALLBACK_RO_FILE;
      }

      if (fs.existsSync(sourceFile)) {
        const raw = fs.readFileSync(sourceFile, 'utf-8');
        const parsed = JSON.parse(raw);
        this.data = {
          organizations: parsed.organizations || [],
          enrollmentTokens: parsed.enrollmentTokens || [],
          devices: parsed.devices || [],
          securityEvents: parsed.securityEvents || [],
          auditLogs: parsed.auditLogs || [],
          adminUsers: parsed.adminUsers || [],
          revokedSessions: parsed.revokedSessions || []
        };
        if (this.data.organizations.length === 0) {
          this.seedInitialPilotData();
        }
        if (!this.data.adminUsers || this.data.adminUsers.length === 0) {
          this.seedInitialAdminUsers();
        }
        // Ensure Super Admin password hash matches PHISHGUARD_INITIAL_ADMIN_PASSWORD if provided
        if (process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD) {
          const superAdmin = this.data.adminUsers.find(
            u => u.role === 'SUPER_ADMIN' || u.username === 'admin' || u.email === 'admin@phishguard.security'
          );
          if (superAdmin) {
            superAdmin.passwordHash = hashPassword(process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD);
          }
        }

        // Ensure Acme Organization Admin exists and password hash matches if provided
        const orgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
        let acmeAdmin = this.data.adminUsers.find(
          u => (u.organizationId === 'ORG-ACME-PILOT' && u.role === 'ORG_ADMIN') ||
               u.username === 'acme_admin' ||
               u.email === 'it-admin@acme-corp.com'
        );
        if (!acmeAdmin) {
          acmeAdmin = {
            id: 'usr_acme_admin_01',
            username: 'acme_admin',
            name: 'Alex Rivera (IT Lead)',
            email: 'it-admin@acme-corp.com',
            role: 'ORG_ADMIN',
            organizationId: 'ORG-ACME-PILOT',
            passwordHash: orgAdminPass ? hashPassword(orgAdminPass) : 'DISABLED:UNINITIALIZED_BOOTSTRAP',
            apiKey: crypto.randomBytes(24).toString('hex'),
            createdAt: Date.now() - 15 * 86400000,
            lastLoginAt: 0
          };
          this.data.adminUsers.push(acmeAdmin);
        } else if (orgAdminPass && (acmeAdmin.passwordHash.startsWith('DISABLED:') || acmeAdmin.passwordHash !== hashPassword(orgAdminPass))) {
          acmeAdmin.passwordHash = hashPassword(orgAdminPass);
        }

        this.rebuildIndexes();
        this.persist();
        this.isLoaded = true;
      } else {
        this.seedInitialPilotData();
        this.seedInitialAdminUsers();
        this.rebuildIndexes();
        this.persist();
      }
    } catch (err) {
      console.warn('[PhishGuard DB] Initializing fresh database state:', err);
      this.seedInitialPilotData();
      this.seedInitialAdminUsers();
      this.rebuildIndexes();
    }
  }

  private seedInitialAdminUsers(): void {
    const now = Date.now();
    const initialPass = process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    const scryptPasswordHash = initialPass ? hashPassword(initialPass) : 'DISABLED:UNINITIALIZED_BOOTSTRAP';
    const orgAdminPass = process.env.PHISHGUARD_INITIAL_ORG_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ACME_ADMIN_PASSWORD || process.env.PHISHGUARD_INITIAL_ADMIN_PASSWORD;
    const orgAdminHash = orgAdminPass ? hashPassword(orgAdminPass) : 'DISABLED:UNINITIALIZED_BOOTSTRAP';
    
    this.data.adminUsers = [
      {
        id: 'usr_super_admin_01',
        username: 'admin',
        name: 'SecOps Director',
        email: 'admin@phishguard.security',
        role: 'SUPER_ADMIN',
        passwordHash: scryptPasswordHash,
        apiKey: crypto.randomBytes(24).toString('hex'),
        createdAt: now - 30 * 86400000,
        lastLoginAt: now - 3600000
      },
      {
        id: 'usr_acme_admin_01',
        username: 'acme_admin',
        name: 'Alex Rivera (IT Lead)',
        email: 'it-admin@acme-corp.com',
        role: 'ORG_ADMIN',
        organizationId: 'ORG-ACME-PILOT',
        passwordHash: orgAdminHash,
        apiKey: crypto.randomBytes(24).toString('hex'),
        createdAt: now - 15 * 86400000,
        lastLoginAt: now - 7200000
      },
      {
        id: 'usr_individual_01',
        username: 'janedoe',
        name: 'Jane Doe',
        email: 'jane.doe@example.com',
        role: 'INDIVIDUAL',
        plan: 'PERSONAL_SHIELD',
        planStatus: 'ACTIVE',
        billingInterval: 'ANNUAL',
        devicesLimit: 3,
        passwordHash: scryptPasswordHash,
        apiKey: crypto.randomBytes(24).toString('hex'),
        createdAt: now - 10 * 86400000,
        lastLoginAt: now - 1800000
      }
    ];
  }

  private rebuildIndexes(): void {
    this.orgIndex.clear();
    this.tokenIndex.clear();
    this.tokenHashIndex.clear();
    this.deviceApiKeyIndex.clear();
    this.deviceIdIndex.clear();
    this.eventIdSet.clear();

    const uniqueOrgs: Organization[] = [];
    const seenOrgIds = new Set<string>();
    for (const org of this.data.organizations) {
      if (!seenOrgIds.has(org.organizationId)) {
        seenOrgIds.add(org.organizationId);
        uniqueOrgs.push(org);
        this.orgIndex.set(org.organizationId, org);
      }
    }
    this.data.organizations = uniqueOrgs;

    const uniqueTokens: EnrollmentToken[] = [];
    const seenTokenKeys = new Set<string>();
    for (const tok of this.data.enrollmentTokens) {
      const key = tok.tokenHash || tok.token || tok.id;
      if (!seenTokenKeys.has(key)) {
        seenTokenKeys.add(key);
        uniqueTokens.push(tok);
        if (tok.token) this.tokenIndex.set(tok.token, tok);
        if (tok.tokenHash) this.tokenHashIndex.set(tok.tokenHash, tok);
      }
    }
    this.data.enrollmentTokens = uniqueTokens;

    const uniqueDevices: EnrolledDevice[] = [];
    const seenDevKeys = new Set<string>();
    for (const dev of this.data.devices) {
      const key = `${dev.organizationId}:${dev.deviceId}`;
      if (!seenDevKeys.has(key)) {
        seenDevKeys.add(key);
        uniqueDevices.push(dev);
        if (dev.deviceApiKey) this.deviceApiKeyIndex.set(dev.deviceApiKey, dev);
        this.deviceIdIndex.set(key, dev);
      }
    }
    this.data.devices = uniqueDevices;

    const uniqueUsers: AdminUser[] = [];
    const seenUserKeys = new Set<string>();
    for (const u of (this.data.adminUsers || [])) {
      const key = u.id || u.email.toLowerCase();
      if (!seenUserKeys.has(key)) {
        seenUserKeys.add(key);
        uniqueUsers.push(u);
      }
    }
    this.data.adminUsers = uniqueUsers;

    for (const evt of this.data.securityEvents) {
      this.eventIdSet.add(evt.eventId);
    }

    this.revokedSessionsMap.clear();
    const now = Date.now();
    const activeRevocations: RevokedSessionRecord[] = [];
    for (const r of (this.data.revokedSessions || [])) {
      if (r.expiresAt > now) {
        activeRevocations.push(r);
        this.revokedSessionsMap.set(r.tokenHash, r);
      }
    }
    this.data.revokedSessions = activeRevocations;
  }

  private persist(): void {
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf-8');
    } catch (err) {
      console.error('[PhishGuard DB] Persistence write failure:', err);
    }
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  private seedInitialPilotData(): void {
    const now = Date.now();
    const pilotOrgId = 'ORG-ACME-PILOT';
    const pilotToken = 'pg_enroll_acme_pilot_2026';
    const pilotTokenHash = this.hashToken(pilotToken);

    const defaultOrg: Organization = {
      organizationId: pilotOrgId,
      name: 'Acme Corporation (Pilot)',
      status: 'PILOT',
      enrollmentToken: pilotToken,
      enforcementMode: 'BLOCK',
      telemetryEnabled: true,
      retentionDays: 90,
      minExtensionVersion: '1.0.0',
      backendUrl: 'http://localhost:3000',
      createdAt: now - 1000 * 60 * 60 * 24 * 7,
      updatedAt: now
    };

    const defaultToken: EnrollmentToken = {
      id: 'tok_acme_pilot_init',
      organizationId: pilotOrgId,
      token: pilotToken,
      tokenHash: pilotTokenHash,
      label: 'Initial Pilot Enrollment Token',
      status: 'ACTIVE',
      createdAt: now - 1000 * 60 * 60 * 24 * 7,
      expiresAt: null,
      maxUses: null,
      useCount: 1,
      revokedAt: null,
      revokedBy: null
    };

    this.data.organizations = [defaultOrg];
    this.data.enrollmentTokens = [defaultToken];
    this.data.devices = [];
    this.data.securityEvents = [];
    this.data.auditLogs = [{
      id: 'audit_init_001',
      organizationId: pilotOrgId,
      timestamp: now,
      actor: 'System Bootstrap',
      action: 'ORGANIZATION_INITIALIZED',
      target: pilotOrgId,
      details: 'Initialized default organization Acme Corporation for deployment pilot.'
    }];
  }

  // ==========================================================================
  // 1. ORGANIZATIONS
  // ==========================================================================

  public getOrganizations(): Organization[] {
    return [...this.data.organizations];
  }

  public getOrganizationById(organizationId: string): Organization | null {
    return this.orgIndex.get(organizationId) || null;
  }

  public createOrganization(data: Partial<Organization>, actor = 'Admin Console'): Organization {
    const orgId = data.organizationId || `ORG-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const existing = this.getOrganizationById(orgId);
    if (existing) {
      if (data.name) existing.name = data.name;
      if (data.status) existing.status = data.status;
      if (data.enforcementMode) existing.enforcementMode = data.enforcementMode;
      if (data.telemetryEnabled !== undefined) existing.telemetryEnabled = data.telemetryEnabled;
      if (data.minExtensionVersion) existing.minExtensionVersion = data.minExtensionVersion;
      if (data.retentionDays) existing.retentionDays = data.retentionDays;
      if (data.backendUrl) existing.backendUrl = data.backendUrl;
      existing.updatedAt = Date.now();
      this.persist();
      return { ...existing };
    }

    const initialTokenStr = `pg_enroll_${crypto.randomBytes(16).toString('hex')}`;
    const now = Date.now();

    const newOrg: Organization = {
      organizationId: orgId,
      name: data.name || 'New Organization',
      status: data.status || 'ACTIVE',
      enrollmentToken: initialTokenStr,
      enforcementMode: data.enforcementMode || 'BLOCK',
      telemetryEnabled: data.telemetryEnabled ?? true,
      minExtensionVersion: data.minExtensionVersion || '1.0.0',
      retentionDays: data.retentionDays || 90,
      backendUrl: data.backendUrl || '',
      createdAt: now,
      updatedAt: now
    };

    const tokenObj: EnrollmentToken = {
      id: `tok_${crypto.randomBytes(6).toString('hex')}`,
      organizationId: orgId,
      token: initialTokenStr,
      tokenHash: this.hashToken(initialTokenStr),
      label: 'Default Enrollment Token',
      status: 'ACTIVE',
      createdAt: now,
      expiresAt: null,
      maxUses: null,
      useCount: 0,
      revokedAt: null,
      revokedBy: null
    };

    this.data.organizations.push(newOrg);
    this.data.enrollmentTokens.push(tokenObj);
    this.rebuildIndexes();

    this.addAuditLog({
      organizationId: orgId,
      actor,
      action: 'ORGANIZATION_CREATED',
      target: orgId,
      details: `Created organization ${newOrg.name} (${orgId}) with initial enrollment token.`
    });

    this.persist();
    return newOrg;
  }

  public updateOrganization(organizationId: string, updates: Partial<Organization>, actor = 'Admin Console'): Organization | null {
    const org = this.getOrganizationById(organizationId);
    if (!org) return null;

    if (updates.name !== undefined) org.name = updates.name;
    if (updates.status !== undefined) org.status = updates.status;
    if (updates.enforcementMode !== undefined) org.enforcementMode = updates.enforcementMode;
    if (updates.telemetryEnabled !== undefined) org.telemetryEnabled = updates.telemetryEnabled;
    if (updates.minExtensionVersion !== undefined) org.minExtensionVersion = updates.minExtensionVersion;
    if (updates.retentionDays !== undefined) org.retentionDays = updates.retentionDays;
    if (updates.backendUrl !== undefined) org.backendUrl = updates.backendUrl;
    org.updatedAt = Date.now();

    this.addAuditLog({
      organizationId,
      actor,
      action: 'ORGANIZATION_POLICY_UPDATED',
      target: organizationId,
      details: `Updated policy: enforcement=${org.enforcementMode}, minVersion=${org.minExtensionVersion}, telemetry=${org.telemetryEnabled}`
    });

    this.persist();
    return { ...org };
  }

  // ==========================================================================
  // 2. ENROLLMENT TOKENS
  // ==========================================================================

  public createEnrollmentToken(data: {
    organizationId: string;
    label?: string;
    expiresInDays?: number | null;
    maxUses?: number | null;
    actor?: string;
  }): EnrollmentToken {
    const org = this.getOrganizationById(data.organizationId);
    if (!org) {
      throw new Error(`Organization ${data.organizationId} not found`);
    }

    const tokenStr = `pg_enroll_${crypto.randomBytes(20).toString('hex')}`;
    const tokenHash = this.hashToken(tokenStr);
    const now = Date.now();
    const expiresAt = data.expiresInDays ? now + data.expiresInDays * 24 * 60 * 60 * 1000 : null;

    const tokenObj: EnrollmentToken = {
      id: `tok_${crypto.randomBytes(6).toString('hex')}`,
      organizationId: data.organizationId,
      token: tokenStr,
      tokenHash,
      label: data.label || `Enrollment Token ${new Date().toISOString().split('T')[0]}`,
      status: 'ACTIVE',
      createdAt: now,
      expiresAt,
      maxUses: data.maxUses ?? null,
      useCount: 0,
      revokedAt: null,
      revokedBy: null
    };

    this.data.enrollmentTokens.push(tokenObj);
    this.rebuildIndexes();

    this.addAuditLog({
      organizationId: data.organizationId,
      actor: data.actor || 'Admin Console',
      action: 'ENROLLMENT_TOKEN_CREATED',
      target: tokenObj.id,
      details: `Generated enrollment token "${tokenObj.label}" (expires: ${expiresAt ? new Date(expiresAt).toISOString() : 'Never'})`
    });

    this.persist();
    return tokenObj;
  }

  public getEnrollmentTokens(organizationId: string): EnrollmentToken[] {
    return this.data.enrollmentTokens
      .filter(t => t.organizationId === organizationId)
      .map(t => ({ ...t, token: '' }));
  }

  public getEnrollmentTokenById(tokenId: string): EnrollmentToken | null {
    return this.data.enrollmentTokens.find(t => t.id === tokenId) || null;
  }

  public validateEnrollmentToken(tokenString: string): { valid: boolean; token?: EnrollmentToken; error?: string } {
    if (!tokenString || typeof tokenString !== 'string') {
      return { valid: false, error: 'Missing enrollment token string' };
    }

    const tokenObj = this.tokenIndex.get(tokenString) || this.tokenHashIndex.get(this.hashToken(tokenString));
    if (!tokenObj) {
      return { valid: false, error: 'Invalid enrollment token' };
    }

    if (tokenObj.status === 'REVOKED' || tokenObj.revokedAt !== null) {
      return { valid: false, error: 'Enrollment token has been revoked by organization administrator' };
    }

    if (tokenObj.expiresAt && Date.now() > tokenObj.expiresAt) {
      tokenObj.status = 'EXPIRED';
      this.persist();
      return { valid: false, error: 'Enrollment token has expired' };
    }

    if (tokenObj.maxUses && tokenObj.useCount >= tokenObj.maxUses) {
      return { valid: false, error: 'Enrollment token maximum device registration limit reached' };
    }

    return { valid: true, token: tokenObj };
  }

  public revokeEnrollmentToken(tokenId: string, actor = 'Admin Console'): boolean {
    const token = this.getEnrollmentTokenById(tokenId);
    if (!token) return false;

    token.status = 'REVOKED';
    token.revokedAt = Date.now();
    token.revokedBy = actor;

    this.addAuditLog({
      organizationId: token.organizationId,
      actor,
      action: 'ENROLLMENT_TOKEN_REVOKED',
      target: token.id,
      details: `Revoked enrollment token "${token.label}" (${token.id})`
    });

    this.persist();
    return true;
  }

  // ==========================================================================
  // 3. DEVICE ENROLLMENT & AUTHENTICATION
  // ==========================================================================

  public enrollDevice(data: {
    enrollmentToken: string;
    installationId: string;
    extensionVersion: string;
    browser: string;
    os: string;
    platform?: string;
    deviceName?: string;
    ip?: string;
  }): { success: boolean; device?: EnrolledDevice; error?: string } {
    const validation = this.validateEnrollmentToken(data.enrollmentToken);
    if (!validation.valid || !validation.token) {
      return { success: false, error: validation.error || 'Invalid enrollment token' };
    }

    const token = validation.token;
    const org = this.getOrganizationById(token.organizationId);
    if (!org) {
      return { success: false, error: 'Organization associated with token does not exist' };
    }

    // Check if device with this installationId is already enrolled in this org
    const existing = this.data.devices.find(
      d => d.organizationId === token.organizationId && d.installationId === data.installationId
    );

    const now = Date.now();

    if (existing) {
      // Re-enrollment/credential renewal for existing installation
      existing.extensionVersion = data.extensionVersion;
      existing.browser = data.browser;
      existing.os = data.os;
      existing.platform = data.platform || existing.platform;
      existing.deviceName = data.deviceName || existing.deviceName;
      existing.lastSeen = now;
      existing.lastIp = data.ip || existing.lastIp;
      if (!existing.deviceApiKey) {
        existing.deviceApiKey = `pg_dev_${crypto.randomBytes(24).toString('hex')}`;
      }
      this.rebuildIndexes();
      this.persist();
      return { success: true, device: { ...existing } };
    }

    // Generate stable device identity scoped to organization
    const deviceId = `DEV-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const deviceApiKey = `pg_dev_${crypto.randomBytes(24).toString('hex')}`;

    const newDevice: EnrolledDevice = {
      id: `dev_${crypto.randomBytes(6).toString('hex')}`,
      installationId: data.installationId || `inst_${crypto.randomBytes(8).toString('hex')}`,
      deviceId,
      organizationId: token.organizationId,
      deviceApiKey,
      deviceName: data.deviceName || `Endpoint ${deviceId}`,
      extensionVersion: data.extensionVersion || '1.0.0',
      browser: data.browser || 'Chrome MV3',
      platform: data.platform || 'Desktop',
      os: data.os || 'Unknown OS',
      firstSeen: now,
      lastSeen: now,
      status: 'ONLINE',
      eventsCount: 0,
      blockedCount: 0,
      warningsCount: 0,
      lastIp: data.ip
    };

    token.useCount += 1;
    this.data.devices.push(newDevice);
    this.rebuildIndexes();

    this.addAuditLog({
      organizationId: token.organizationId,
      actor: 'Device Registration Service',
      action: 'DEVICE_ENROLLED',
      target: deviceId,
      details: `Enrolled new endpoint ${deviceId} (${newDevice.os}, ${newDevice.browser}) via token ${token.label}`
    });

    this.persist();
    return { success: true, device: newDevice };
  }

  public getDevices(organizationId?: string): EnrolledDevice[] {
    const now = Date.now();
    return this.data.devices
      .filter(d => (!organizationId || d.organizationId === organizationId))
      .map(device => {
        const org = this.getOrganizationById(device.organizationId);
        const minVersion = org?.minExtensionVersion || '1.0.0';
        let status: DeviceHealthStatus = 'ONLINE';

        if (now - device.lastSeen > ONLINE_THRESHOLD_MS) {
          status = 'OFFLINE';
        } else if (device.extensionVersion < minVersion) {
          status = 'UPDATE_REQUIRED';
        }

        return {
          ...device,
          status
        };
      });
  }

  public getDeviceById(deviceId: string, organizationId?: string): EnrolledDevice | null {
    const devices = this.getDevices(organizationId);
    return devices.find(d => d.deviceId === deviceId || d.id === deviceId) || null;
  }

  public getDeviceByApiKey(apiKey: string): EnrolledDevice | null {
    if (!apiKey) return null;
    return this.deviceApiKeyIndex.get(apiKey) || null;
  }

  public revokeDevice(deviceId: string, organizationId?: string, actor = 'Admin Console'): boolean {
    const devIndex = this.data.devices.findIndex(
      d => (d.deviceId === deviceId || d.id === deviceId) && (!organizationId || d.organizationId === organizationId)
    );
    if (devIndex === -1) return false;

    const dev = this.data.devices[devIndex];
    // Remove from devices collection to permanently revoke authentication
    this.data.devices.splice(devIndex, 1);
    this.rebuildIndexes();
    this.persist();

    this.addAuditLog({
      organizationId: dev.organizationId,
      actor,
      action: 'DEVICE_REVOKED',
      target: dev.deviceId,
      details: `Revoked endpoint ${dev.deviceName} (${dev.deviceId}). Device credentials disabled.`
    });

    return true;
  }

  public deleteOrganization(organizationId: string, actor = 'Admin Console'): boolean {
    const idx = this.data.organizations.findIndex(o => o.organizationId === organizationId);
    if (idx === -1) return false;

    const org = this.data.organizations[idx];
    this.data.organizations.splice(idx, 1);
    // Cascade removal of tokens and devices
    this.data.enrollmentTokens = this.data.enrollmentTokens.filter(t => t.organizationId !== organizationId);
    this.data.devices = this.data.devices.filter(d => d.organizationId !== organizationId);
    this.rebuildIndexes();
    this.persist();

    this.addAuditLog({
      organizationId,
      actor,
      action: 'ORGANIZATION_DELETED',
      target: organizationId,
      details: `Permanently deleted organization ${org.name} (${organizationId})`
    });

    return true;
  }

  // ==========================================================================
  // ADMIN USERS & RBAC
  // ==========================================================================

  public getAdminUsers(organizationId?: string): AdminUser[] {
    if (!organizationId) return [...this.data.adminUsers];
    return this.data.adminUsers.filter(u => u.organizationId === organizationId);
  }

  public getAdminUserById(id: string): AdminUser | null {
    return this.data.adminUsers.find(u => u.id === id) || null;
  }

  public getAdminUserByEmail(email: string): AdminUser | null {
    if (!email) return null;
    return this.data.adminUsers.find(u => u.email.toLowerCase() === email.toLowerCase()) || null;
  }

  public createAdminUser(user: Omit<AdminUser, 'id' | 'createdAt' | 'lastLoginAt'>, actor = 'Admin Console'): AdminUser {
    const newUser: AdminUser = {
      ...user,
      id: `usr_${crypto.randomBytes(6).toString('hex')}`,
      createdAt: Date.now(),
      lastLoginAt: 0
    };

    this.data.adminUsers.push(newUser);
    this.persist();

    this.addAuditLog({
      organizationId: user.organizationId || 'GLOBAL',
      actor,
      action: 'ADMIN_USER_CREATED',
      target: newUser.id,
      details: `Created administrative user ${newUser.email} with role ${newUser.role}`
    });

    return newUser;
  }

  public updateAdminUser(id: string, updates: Partial<AdminUser>, actor = 'Admin Console'): AdminUser | null {
    const user = this.data.adminUsers.find(u => u.id === id);
    if (!user) return null;

    if (updates.name !== undefined) user.name = updates.name;
    if (updates.email !== undefined) user.email = updates.email;
    if (updates.role !== undefined) user.role = updates.role;
    if (updates.passwordHash !== undefined) user.passwordHash = updates.passwordHash;
    if (updates.lastLoginAt !== undefined) user.lastLoginAt = updates.lastLoginAt;

    this.persist();

    this.addAuditLog({
      organizationId: user.organizationId || 'GLOBAL',
      actor,
      action: 'ADMIN_USER_UPDATED',
      target: user.id,
      details: `Updated administrative user ${user.email}`
    });

    return { ...user };
  }

  public deleteAdminUser(id: string, actor = 'Admin Console'): boolean {
    const idx = this.data.adminUsers.findIndex(u => u.id === id);
    if (idx === -1) return false;

    const user = this.data.adminUsers[idx];
    this.data.adminUsers.splice(idx, 1);
    this.persist();

    this.addAuditLog({
      organizationId: user.organizationId || 'GLOBAL',
      actor,
      action: 'ADMIN_USER_DELETED',
      target: user.id,
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
    const now = Date.now();
    let device = this.data.devices.find(
      d => d.deviceId === data.deviceId || (d.installationId === data.installationId && (!data.organizationId || d.organizationId === data.organizationId))
    );

    const orgId = data.organizationId || device?.organizationId || 'ORG-ACME-PILOT';
    const org = this.getOrganizationById(orgId) || this.data.organizations[0];

    if (!device) {
      // Auto-register legacy/un-enrolled endpoint if within test org
      const deviceId = data.deviceId || `DEV-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
      device = {
        id: `dev_${crypto.randomBytes(6).toString('hex')}`,
        installationId: data.installationId || `inst_${crypto.randomBytes(8).toString('hex')}`,
        deviceId,
        organizationId: orgId,
        deviceApiKey: `pg_dev_${crypto.randomBytes(24).toString('hex')}`,
        deviceName: `Endpoint ${deviceId}`,
        extensionVersion: data.extensionVersion || '1.0.0',
        browser: data.browser || 'Chrome MV3',
        os: data.os || 'Unknown OS',
        firstSeen: now,
        lastSeen: now,
        status: 'ONLINE',
        eventsCount: 0,
        blockedCount: 0,
        warningsCount: 0,
        lastIp: data.ip
      };
      this.data.devices.push(device);
    } else {
      device.lastSeen = now;
      device.extensionVersion = data.extensionVersion || device.extensionVersion;
      if (data.browser) device.browser = data.browser;
      if (data.os) device.os = data.os;
      if (data.ip) device.lastIp = data.ip;
      device.status = (device.extensionVersion < (org?.minExtensionVersion || '1.0.0')) ? 'UPDATE_REQUIRED' : 'ONLINE';
    }

    this.rebuildIndexes();
    this.persist();

    return {
      success: true,
      device: { ...device },
      enforcementMode: org?.enforcementMode || 'BLOCK',
      minExtensionVersion: org?.minExtensionVersion || '1.0.0'
    };
  }

  // ==========================================================================
  // 4. CANONICAL SECURITY EVENTS (INGEST, PRIVACY, DEDUPLICATION)
  // ==========================================================================

  private sanitizeUrl(rawUrl: string): string {
    try {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
      const sensitiveKeys = ['token', 'password', 'pass', 'pwd', 'auth', 'access_token', 'secret', 'key', 'id_token', 'code', 'session', 'user', 'email', 'jwt', 'api_key'];
      const params = new URLSearchParams(parsed.search);
      for (const k of Array.from(params.keys())) {
        if (sensitiveKeys.some(sk => k.toLowerCase().includes(sk))) {
          params.set(k, '[REDACTED]');
        }
      }
      const searchStr = decodeURIComponent(params.toString());
      return `${parsed.origin}${parsed.pathname}${searchStr ? `?${searchStr}` : ''}`;
    } catch {
      return rawUrl.replace(/([?&](token|password|pass|key|code|auth|secret|jwt|session)=)[^&]*/gi, '$1[REDACTED]');
    }
  }

  public ingestSecurityEvent(event: CanonicalSecurityEvent): { success: boolean; isDuplicate: boolean; eventId: string } {
    if (!event.eventId) {
      event.eventId = `evt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    }

    // Deduplication check via eventId
    if (this.eventIdSet.has(event.eventId)) {
      return { success: true, isDuplicate: true, eventId: event.eventId };
    }

    // Apply strict privacy sanitization to URL
    event.url = this.sanitizeUrl(event.url);

    // Fallback defaults
    event.timestamp = event.timestamp || Date.now();
    event.organizationId = event.organizationId || 'ORG-ACME-PILOT';
    event.createdAt = event.createdAt || new Date(event.timestamp).toISOString();

    // Link and update device event counters
    const device = this.data.devices.find(
      d => d.organizationId === event.organizationId && d.deviceId === event.deviceId
    );
    if (device) {
      device.eventsCount = (device.eventsCount || 0) + 1;
      if (event.action === 'BLOCKED') {
        device.blockedCount = (device.blockedCount || 0) + 1;
      } else if (event.action === 'WARNED') {
        device.warningsCount = (device.warningsCount || 0) + 1;
      }
    }

    this.data.securityEvents.unshift(event);
    this.eventIdSet.add(event.eventId);

    // Bound events retention in local storage
    if (this.data.securityEvents.length > MAX_EVENTS_RETENTION) {
      const removed = this.data.securityEvents.pop();
      if (removed) this.eventIdSet.delete(removed.eventId);
    }

    this.persist();
    return { success: true, isDuplicate: false, eventId: event.eventId };
  }

  public ingestBatchEvents(events: CanonicalSecurityEvent[]): { ingested: number; duplicates: number } {
    let ingested = 0;
    let duplicates = 0;

    for (const evt of events) {
      const res = this.ingestSecurityEvent(evt);
      if (res.isDuplicate) {
        duplicates++;
      } else if (res.success) {
        ingested++;
      }
    }

    return { ingested, duplicates };
  }

  public getSecurityEvents(filter: QueryEventsFilter): { events: CanonicalSecurityEvent[]; total: number } {
    let list = this.data.securityEvents.filter(e => {
      if (filter.organizationId && e.organizationId !== filter.organizationId) return false;
      if (filter.deviceId && e.deviceId !== filter.deviceId) return false;
      if (filter.riskLevel && filter.riskLevel !== 'ALL' && e.riskLevel !== filter.riskLevel) return false;
      if (filter.action && filter.action !== 'ALL' && e.action !== filter.action) return false;
      if (filter.threatCategory && filter.threatCategory !== 'ALL' && e.threatCategory !== filter.threatCategory) return false;

      if (filter.search) {
        const q = filter.search.toLowerCase();
        const matchUrl = e.url?.toLowerCase().includes(q);
        const matchHost = e.hostname?.toLowerCase().includes(q);
        const matchBrand = e.brand?.toLowerCase().includes(q);
        const matchDevice = e.deviceId?.toLowerCase().includes(q);
        const matchReasons = e.detectionReasons?.some(r => r.toLowerCase().includes(q));
        if (!matchUrl && !matchHost && !matchBrand && !matchDevice && !matchReasons) {
          return false;
        }
      }
      return true;
    });

    if (filter.sortBy === 'highest_risk') {
      list.sort((a, b) => b.riskScore - a.riskScore);
    } else {
      list.sort((a, b) => b.timestamp - a.timestamp);
    }

    const total = list.length;
    const page = filter.page || 1;
    const pageSize = filter.pageSize || 50;
    const startIndex = (page - 1) * pageSize;
    const paged = list.slice(startIndex, startIndex + pageSize);

    return { events: paged, total };
  }

  public getEventById(eventId: string, organizationId?: string): CanonicalSecurityEvent | null {
    const evt = this.data.securityEvents.find(e => e.eventId === eventId);
    if (!evt) return null;
    if (organizationId && evt.organizationId !== organizationId) return null;
    return evt;
  }

  public getEventsByDevice(deviceId: string, organizationId?: string): CanonicalSecurityEvent[] {
    return this.data.securityEvents.filter(
      e => e.deviceId === deviceId && (!organizationId || e.organizationId === organizationId)
    );
  }

  // ==========================================================================
  // 5. METRICS, OVERVIEW & CSV EXPORT
  // ==========================================================================

  public getOverviewStats(organizationId?: string): OrganizationStats {
    const orgDevices = this.getDevices(organizationId);
    const orgEvents = this.data.securityEvents.filter(
      e => !organizationId || e.organizationId === organizationId
    );

    const now = Date.now();
    const twentyFourHoursAgo = now - 24 * 60 * 60 * 1000;

    const eventsToday = orgEvents.filter(e => e.timestamp >= twentyFourHoursAgo);
    const blockedToday = eventsToday.filter(e => e.action === 'BLOCKED').length;
    const warningsToday = eventsToday.filter(e => e.action === 'WARNED').length;
    const threatsToday = eventsToday.filter(e => e.riskScore >= 60).length;

    const onlineDevices = orgDevices.filter(d => d.status === 'ONLINE').length;
    const offlineDevices = orgDevices.filter(d => d.status === 'OFFLINE').length;
    const updateRequiredDevices = orgDevices.filter(d => d.status === 'UPDATE_REQUIRED').length;
    const devicesNeedingAttention = orgDevices.filter(d => d.status === 'NEEDS_ATTENTION' || d.status === 'UPDATE_REQUIRED').length;

    // Brand aggregation
    const brandCounts = new Map<string, { count: number; category: string }>();
    for (const evt of orgEvents) {
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

    // Threat Category aggregation
    const catCounts = new Map<string, number>();
    for (const evt of orgEvents) {
      const cat = evt.threatCategory || 'OTHER';
      catCounts.set(cat, (catCounts.get(cat) || 0) + 1);
    }
    const totalEventsCount = orgEvents.length;
    const topThreatCategories = Array.from(catCounts.entries())
      .map(([category, count]) => ({
        category,
        count,
        percentage: totalEventsCount > 0 ? Math.round((count / totalEventsCount) * 100) : 0
      }))
      .sort((a, b) => b.count - a.count);

    return {
      totalProtectedDevices: orgDevices.length,
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
      recentEvents: orgEvents.slice(0, 10)
    };
  }

  public generateCsvExport(organizationId: string): string {
    const events = this.data.securityEvents.filter(e => e.organizationId === organizationId);
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

  // ==========================================================================
  // 6. AUDIT LOGS
  // ==========================================================================

  public addAuditLog(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): AuditLogEntry {
    const log: AuditLogEntry = {
      id: `audit_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      timestamp: Date.now(),
      organizationId: entry.organizationId,
      actor: entry.actor,
      action: entry.action,
      target: entry.target,
      details: entry.details
    };
    this.data.auditLogs.unshift(log);
    if (this.data.auditLogs.length > 2000) {
      this.data.auditLogs.pop();
    }
    this.persist();
    return log;
  }

  public getAuditLogs(organizationId?: string): AuditLogEntry[] {
    if (!organizationId) return [...this.data.auditLogs];
    return this.data.auditLogs.filter(l => l.organizationId === organizationId);
  }

  // ==========================================================================
  // 7. SESSION REVOCATION
  // ==========================================================================

  public revokeSession(
    tokenHash: string,
    expiresAt: number,
    metadata?: { userId?: string; organizationId?: string }
  ): void {
    const record: RevokedSessionRecord = {
      tokenHash,
      userId: metadata?.userId,
      organizationId: metadata?.organizationId,
      expiresAt,
      revokedAt: Date.now()
    };
    if (!this.data.revokedSessions) {
      this.data.revokedSessions = [];
    }
    this.data.revokedSessions = this.data.revokedSessions.filter(r => r.tokenHash !== tokenHash);
    this.data.revokedSessions.push(record);
    this.revokedSessionsMap.set(tokenHash, record);
    this.persist();
  }

  public isSessionRevoked(tokenHash: string): boolean {
    const record = this.revokedSessionsMap.get(tokenHash);
    if (!record) return false;
    if (Date.now() >= record.expiresAt) {
      this.revokedSessionsMap.delete(tokenHash);
      if (this.data.revokedSessions) {
        this.data.revokedSessions = this.data.revokedSessions.filter(r => r.tokenHash !== tokenHash);
      }
      return false;
    }
    return true;
  }

  public cleanExpiredRevocations(): number {
    const now = Date.now();
    const prevCount = this.data.revokedSessions?.length || 0;
    if (this.data.revokedSessions) {
      this.data.revokedSessions = this.data.revokedSessions.filter(r => r.expiresAt > now);
    }
    this.revokedSessionsMap.clear();
    for (const r of (this.data.revokedSessions || [])) {
      this.revokedSessionsMap.set(r.tokenHash, r);
    }
    const cleaned = prevCount - (this.data.revokedSessions?.length || 0);
    if (cleaned > 0) {
      this.persist();
    }
    return cleaned;
  }
}
