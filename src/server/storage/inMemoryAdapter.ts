/**
 * PhishGuard In-Memory Storage Adapter
 * 
 * High-speed in-memory database adapter for fast, isolated automated test suites.
 * Implements the exact same IDatabaseAdapter contract.
 */

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
  OrganizationStats,
  QueryEventsFilter,
  AdminUser,
  RevokedSessionRecord
} from './types';

const ONLINE_THRESHOLD_MS = 5 * 60 * 1000;

export class InMemoryDatabaseAdapter implements IDatabaseAdapter {
  private organizations: Organization[] = [];
  private enrollmentTokens: EnrollmentToken[] = [];
  private devices: EnrolledDevice[] = [];
  private securityEvents: CanonicalSecurityEvent[] = [];
  private auditLogs: AuditLogEntry[] = [];
  private adminUsers: AdminUser[] = [];
  private eventIdSet = new Set<string>();

  public init(): void {
    this.organizations = [];
    this.enrollmentTokens = [];
    this.devices = [];
    this.securityEvents = [];
    this.auditLogs = [];
    this.adminUsers = [];
    this.eventIdSet.clear();
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  public getOrganizations(): Organization[] {
    return [...this.organizations];
  }

  public getOrganizationById(organizationId: string): Organization | null {
    return this.organizations.find(o => o.organizationId === organizationId) || null;
  }

  public createOrganization(data: Partial<Organization>, actor = 'Test Admin'): Organization {
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

    this.organizations.push(newOrg);
    this.enrollmentTokens.push(tokenObj);
    return newOrg;
  }

  public updateOrganization(organizationId: string, updates: Partial<Organization>, actor = 'Test Admin'): Organization | null {
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

    return { ...org };
  }

  public deleteOrganization(organizationId: string, actor = 'Test Admin'): boolean {
    const idx = this.organizations.findIndex(o => o.organizationId === organizationId);
    if (idx === -1) return false;
    this.organizations.splice(idx, 1);
    this.devices = this.devices.filter(d => d.organizationId !== organizationId);
    this.enrollmentTokens = this.enrollmentTokens.filter(t => t.organizationId !== organizationId);
    this.securityEvents = this.securityEvents.filter(e => e.organizationId !== organizationId);
    return true;
  }

  public createEnrollmentToken(data: {
    organizationId: string;
    label?: string;
    expiresInDays?: number | null;
    maxUses?: number | null;
    actor?: string;
  }): EnrollmentToken {
    const org = this.getOrganizationById(data.organizationId);
    if (!org) throw new Error(`Organization ${data.organizationId} not found`);

    const tokenStr = `pg_enroll_${crypto.randomBytes(20).toString('hex')}`;
    const tokenHash = this.hashToken(tokenStr);
    const now = Date.now();
    const expiresAt = data.expiresInDays ? now + data.expiresInDays * 24 * 60 * 60 * 1000 : null;

    const tokenObj: EnrollmentToken = {
      id: `tok_${crypto.randomBytes(6).toString('hex')}`,
      organizationId: data.organizationId,
      token: tokenStr,
      tokenHash,
      label: data.label || 'Test Enrollment Token',
      status: 'ACTIVE',
      createdAt: now,
      expiresAt,
      maxUses: data.maxUses ?? null,
      useCount: 0,
      revokedAt: null,
      revokedBy: null
    };

    this.enrollmentTokens.push(tokenObj);
    return tokenObj;
  }

  public getEnrollmentTokens(organizationId: string): EnrollmentToken[] {
    return this.enrollmentTokens.filter(t => t.organizationId === organizationId);
  }

  public getEnrollmentTokenById(tokenId: string): EnrollmentToken | null {
    return this.enrollmentTokens.find(t => t.id === tokenId) || null;
  }

  public validateEnrollmentToken(tokenString: string): { valid: boolean; token?: EnrollmentToken; error?: string } {
    if (!tokenString) return { valid: false, error: 'Missing enrollment token' };
    const tokenObj = this.enrollmentTokens.find(
      t => t.token === tokenString || t.tokenHash === this.hashToken(tokenString)
    );
    if (!tokenObj) return { valid: false, error: 'Invalid enrollment token' };
    if (tokenObj.status === 'REVOKED') return { valid: false, error: 'Token revoked' };
    if (tokenObj.expiresAt && Date.now() > tokenObj.expiresAt) return { valid: false, error: 'Token expired' };
    if (tokenObj.maxUses && tokenObj.useCount >= tokenObj.maxUses) return { valid: false, error: 'Token max uses exceeded' };
    return { valid: true, token: tokenObj };
  }

  public revokeEnrollmentToken(tokenId: string, actor = 'Test Admin'): boolean {
    const tok = this.getEnrollmentTokenById(tokenId);
    if (!tok) return false;
    tok.status = 'REVOKED';
    tok.revokedAt = Date.now();
    tok.revokedBy = actor;
    return true;
  }

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
      return { success: false, error: validation.error || 'Invalid token' };
    }

    const token = validation.token;
    const existing = this.devices.find(
      d => d.organizationId === token.organizationId && d.installationId === data.installationId
    );

    const now = Date.now();
    if (existing) {
      existing.extensionVersion = data.extensionVersion;
      existing.browser = data.browser;
      existing.os = data.os;
      existing.lastSeen = now;
      if (!existing.deviceApiKey) {
        existing.deviceApiKey = `pg_dev_${crypto.randomBytes(24).toString('hex')}`;
      }
      return { success: true, device: { ...existing } };
    }

    const deviceId = `DEV-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const deviceApiKey = `pg_dev_${crypto.randomBytes(24).toString('hex')}`;

    const newDevice: EnrolledDevice = {
      id: `dev_${crypto.randomBytes(6).toString('hex')}`,
      installationId: data.installationId,
      deviceId,
      organizationId: token.organizationId,
      deviceApiKey,
      deviceName: data.deviceName || `Endpoint ${deviceId}`,
      extensionVersion: data.extensionVersion,
      browser: data.browser,
      platform: data.platform || 'Desktop',
      os: data.os,
      firstSeen: now,
      lastSeen: now,
      status: 'ONLINE',
      eventsCount: 0,
      blockedCount: 0,
      warningsCount: 0,
      lastIp: data.ip
    };

    token.useCount += 1;
    this.devices.push(newDevice);
    return { success: true, device: newDevice };
  }

  public getDevices(organizationId?: string): EnrolledDevice[] {
    const now = Date.now();
    return this.devices
      .filter(d => !organizationId || d.organizationId === organizationId)
      .map(device => {
        const org = this.getOrganizationById(device.organizationId);
        let status: DeviceHealthStatus = 'ONLINE';
        if (now - device.lastSeen > ONLINE_THRESHOLD_MS) {
          status = 'OFFLINE';
        } else if (device.extensionVersion < (org?.minExtensionVersion || '1.0.0')) {
          status = 'UPDATE_REQUIRED';
        }
        return { ...device, status };
      });
  }

  public getDeviceById(deviceId: string, organizationId?: string): EnrolledDevice | null {
    return this.getDevices(organizationId).find(d => d.deviceId === deviceId || d.id === deviceId) || null;
  }

  public getDeviceByApiKey(apiKey: string): EnrolledDevice | null {
    return this.devices.find(d => d.deviceApiKey === apiKey) || null;
  }

  public revokeDevice(deviceId: string, organizationId?: string, actor = 'Test Admin'): boolean {
    const idx = this.devices.findIndex(
      d => (d.deviceId === deviceId || d.id === deviceId) && (!organizationId || d.organizationId === organizationId)
    );
    if (idx === -1) return false;
    this.devices.splice(idx, 1);
    return true;
  }

  // Admin User CRUD
  public getAdminUsers(organizationId?: string): AdminUser[] {
    if (!organizationId) return [...this.adminUsers];
    return this.adminUsers.filter(u => u.organizationId === organizationId || u.role === 'SUPER_ADMIN');
  }

  public getAdminUserById(id: string): AdminUser | null {
    return this.adminUsers.find(u => u.id === id) || null;
  }

  public getAdminUserByEmail(email: string): AdminUser | null {
    const normalized = email.trim().toLowerCase();
    return this.adminUsers.find(u => u.email.toLowerCase() === normalized) || null;
  }

  public createAdminUser(userData: Omit<AdminUser, 'id' | 'createdAt' | 'lastLoginAt'>, actor = 'Test Admin'): AdminUser {
    const newUser: AdminUser = {
      id: `usr_${crypto.randomBytes(6).toString('hex')}`,
      email: userData.email,
      username: userData.username || userData.email.split('@')[0],
      name: userData.name,
      role: userData.role,
      organizationId: userData.organizationId,
      passwordHash: userData.passwordHash || 'hashed_secret',
      createdAt: Date.now(),
      lastLoginAt: null
    };
    this.adminUsers.push(newUser);
    return newUser;
  }

  public updateAdminUser(id: string, updates: Partial<AdminUser>, actor = 'Test Admin'): AdminUser | null {
    const u = this.getAdminUserById(id);
    if (!u) return null;
    if (updates.name !== undefined) u.name = updates.name;
    if (updates.role !== undefined) u.role = updates.role;
    if (updates.organizationId !== undefined) u.organizationId = updates.organizationId;
    if (updates.passwordHash !== undefined) u.passwordHash = updates.passwordHash;
    if (updates.lastLoginAt !== undefined) u.lastLoginAt = updates.lastLoginAt;
    return { ...u };
  }

  public deleteAdminUser(id: string, actor = 'Test Admin'): boolean {
    const idx = this.adminUsers.findIndex(u => u.id === id);
    if (idx === -1) return false;
    this.adminUsers.splice(idx, 1);
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
    let device = this.devices.find(
      d => d.deviceId === data.deviceId || (d.installationId === data.installationId && (!data.organizationId || d.organizationId === data.organizationId))
    );

    const orgId = data.organizationId || device?.organizationId || 'ORG-ACME-PILOT';
    const org = this.getOrganizationById(orgId) || this.organizations[0];

    if (!device) {
      const deviceId = data.deviceId || `DEV-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
      device = {
        id: `dev_${crypto.randomBytes(6).toString('hex')}`,
        installationId: data.installationId,
        deviceId,
        organizationId: orgId,
        deviceApiKey: `pg_dev_${crypto.randomBytes(24).toString('hex')}`,
        deviceName: `Endpoint ${deviceId}`,
        extensionVersion: data.extensionVersion,
        browser: data.browser || 'Chrome MV3',
        os: data.os || 'Unknown OS',
        firstSeen: now,
        lastSeen: now,
        status: 'ONLINE',
        eventsCount: 0,
        blockedCount: 0,
        warningsCount: 0
      };
      this.devices.push(device);
    } else {
      device.lastSeen = now;
      device.extensionVersion = data.extensionVersion;
      if (data.browser) device.browser = data.browser;
      if (data.os) device.os = data.os;
    }

    return {
      success: true,
      device: { ...device },
      enforcementMode: org?.enforcementMode || 'BLOCK',
      minExtensionVersion: org?.minExtensionVersion || '1.0.0'
    };
  }

  private sanitizeUrl(rawUrl: string): string {
    try {
      const parsed = new URL(rawUrl);
      const sensitiveKeys = ['token', 'password', 'pwd', 'auth', 'access_token', 'secret', 'key', 'id_token', 'code', 'session', 'user', 'email'];
      const params = new URLSearchParams(parsed.search);
      for (const k of Array.from(params.keys())) {
        if (sensitiveKeys.some(sk => k.toLowerCase().includes(sk))) {
          params.delete(k);
        }
      }
      const safeSearch = params.toString() ? `?${params.toString()}` : '';
      return `${parsed.protocol}//${parsed.hostname}${parsed.pathname}${safeSearch}`;
    } catch {
      return rawUrl.split('?')[0].split('#')[0];
    }
  }

  public ingestSecurityEvent(event: CanonicalSecurityEvent): { success: boolean; isDuplicate: boolean; eventId: string } {
    if (!event.eventId) {
      event.eventId = `evt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    }

    if (this.eventIdSet.has(event.eventId)) {
      return { success: true, isDuplicate: true, eventId: event.eventId };
    }

    event.url = this.sanitizeUrl(event.url);
    event.timestamp = event.timestamp || Date.now();
    event.createdAt = event.createdAt || new Date(event.timestamp).toISOString();

    const device = this.devices.find(
      d => d.organizationId === event.organizationId && d.deviceId === event.deviceId
    );
    if (device) {
      device.eventsCount = (device.eventsCount || 0) + 1;
      if (event.action === 'BLOCKED') device.blockedCount = (device.blockedCount || 0) + 1;
      else if (event.action === 'WARNED') device.warningsCount = (device.warningsCount || 0) + 1;
    }

    this.securityEvents.unshift(event);
    this.eventIdSet.add(event.eventId);
    return { success: true, isDuplicate: false, eventId: event.eventId };
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
    const list = this.securityEvents.filter(e => {
      if (filter.organizationId && e.organizationId !== filter.organizationId) return false;
      if (filter.deviceId && e.deviceId !== filter.deviceId) return false;
      if (filter.riskLevel && filter.riskLevel !== 'ALL' && e.riskLevel !== filter.riskLevel) return false;
      if (filter.action && filter.action !== 'ALL' && e.action !== filter.action) return false;
      return true;
    });

    const page = filter.page || 1;
    const pageSize = filter.pageSize || 50;
    const startIndex = (page - 1) * pageSize;
    return { events: list.slice(startIndex, startIndex + pageSize), total: list.length };
  }

  public getEventById(eventId: string, organizationId?: string): CanonicalSecurityEvent | null {
    const evt = this.securityEvents.find(e => e.eventId === eventId);
    if (!evt) return null;
    if (organizationId && evt.organizationId !== organizationId) return null;
    return evt;
  }

  public getEventsByDevice(deviceId: string, organizationId?: string): CanonicalSecurityEvent[] {
    return this.securityEvents.filter(
      e => e.deviceId === deviceId && (!organizationId || e.organizationId === organizationId)
    );
  }

  public getOverviewStats(organizationId?: string): OrganizationStats {
    const orgDevices = this.getDevices(organizationId);
    const orgEvents = this.securityEvents.filter(
      e => !organizationId || e.organizationId === organizationId
    );

    const now = Date.now();
    const twentyFourHoursAgo = now - 24 * 60 * 60 * 1000;
    const eventsToday = orgEvents.filter(e => e.timestamp >= twentyFourHoursAgo);

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
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      totalProtectedDevices: orgDevices.length,
      onlineDevices: orgDevices.filter(d => d.status === 'ONLINE').length,
      offlineDevices: orgDevices.filter(d => d.status === 'OFFLINE').length,
      updateRequiredDevices: orgDevices.filter(d => d.status === 'UPDATE_REQUIRED').length,
      devicesNeedingAttention: orgDevices.filter(d => d.status === 'NEEDS_ATTENTION' || d.status === 'UPDATE_REQUIRED').length,
      threatsToday: eventsToday.filter(e => e.riskScore >= 60).length,
      blockedToday: eventsToday.filter(e => e.action === 'BLOCKED').length,
      warningsToday: eventsToday.filter(e => e.action === 'WARNED').length,
      totalEventsCount: orgEvents.length,
      topTargetedBrands,
      topThreatCategories,
      recentEvents: orgEvents.slice(0, 10)
    };
  }

  public generateCsvExport(organizationId: string): string {
    const events = this.securityEvents.filter(e => e.organizationId === organizationId);
    const headers = ['EventID', 'TimestampISO', 'OrganizationID', 'DeviceID', 'Action', 'RiskLevel', 'RiskScore', 'Hostname', 'SanitizedURL'];
    const rows = events.map(e => [
      e.eventId,
      new Date(e.timestamp).toISOString(),
      e.organizationId,
      e.deviceId,
      e.action,
      e.riskLevel,
      String(e.riskScore),
      e.hostname,
      `"${e.url}"`
    ]);
    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  }

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
    this.auditLogs.unshift(log);
    return log;
  }

  public getAuditLogs(organizationId?: string): AuditLogEntry[] {
    if (!organizationId) return [...this.auditLogs];
    return this.auditLogs.filter(l => l.organizationId === organizationId);
  }

  // Centralized persistent revocation store shared across in-memory adapter instances
  // (simulating centralized PostgreSQL / Supabase storage across serverless worker instances)
  private static centralizedRevocationStore = new Map<string, RevokedSessionRecord>();

  public static clearCentralizedRevocations(): void {
    InMemoryDatabaseAdapter.centralizedRevocationStore.clear();
  }

  public revokeSession(
    tokenHash: string,
    expiresAt: number,
    metadata?: { userId?: string; organizationId?: string }
  ): void {
    InMemoryDatabaseAdapter.centralizedRevocationStore.set(tokenHash, {
      tokenHash,
      userId: metadata?.userId,
      organizationId: metadata?.organizationId,
      expiresAt,
      revokedAt: Date.now()
    });
  }

  public isSessionRevoked(tokenHash: string): boolean {
    const record = InMemoryDatabaseAdapter.centralizedRevocationStore.get(tokenHash);
    if (!record) return false;
    // Safely ignore/prune expired revocation records
    if (Date.now() >= record.expiresAt) {
      InMemoryDatabaseAdapter.centralizedRevocationStore.delete(tokenHash);
      return false;
    }
    return true;
  }

  public cleanExpiredRevocations(): number {
    const now = Date.now();
    let cleaned = 0;
    for (const [hash, record] of InMemoryDatabaseAdapter.centralizedRevocationStore.entries()) {
      if (now >= record.expiresAt) {
        InMemoryDatabaseAdapter.centralizedRevocationStore.delete(hash);
        cleaned++;
      }
    }
    return cleaned;
  }
}
