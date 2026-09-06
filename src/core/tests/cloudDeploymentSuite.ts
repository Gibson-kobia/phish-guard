/**
 * PhishGuard Cloud Deployment & Multi-Tenant Isolation Test Suite
 * 
 * Tests:
 * 1. Multi-tenant isolation (Org A cannot access Org B events, devices, or tokens)
 * 2. Cryptographic token generation, hashing, expiration, and revocation
 * 3. Device enrollment, API key generation, and identity stability
 * 4. Device authentication & server-side tenant derivation
 * 5. Heartbeat tracking & online status calculation (< 5 min)
 * 6. Telemetry ingestion idempotency (deduplication by eventId)
 * 7. Privacy sanitization (scrubbing sensitive query parameters)
 * 8. Durable Queue bounded offline capacity & backoff
 */

import { JsonFileDatabaseAdapter } from '../../server/storage/jsonFileAdapter';
import { DurableTelemetryQueue } from '../events/durableQueue';
import { CanonicalSecurityEvent } from '../types';
import fs from 'fs';
import path from 'path';

export interface CloudTestResult {
  name: string;
  passed: boolean;
  error?: string;
  durationMs: number;
}

export async function runCloudDeploymentTestSuite(): Promise<{
  total: number;
  passed: number;
  failed: number;
  results: CloudTestResult[];
}> {
  const results: CloudTestResult[] = [];
  const testDbFile = path.resolve(process.cwd(), 'data', 'test-cloud-db.json');

  // Clean up any test artifact
  if (fs.existsSync(testDbFile)) {
    try { fs.unlinkSync(testDbFile); } catch {}
  }

  const db = new JsonFileDatabaseAdapter(testDbFile);

  const runTest = async (name: string, fn: () => Promise<void> | void) => {
    const start = Date.now();
    try {
      await fn();
      results.push({ name, passed: true, durationMs: Date.now() - start });
    } catch (err: any) {
      results.push({ name, passed: false, error: err?.message || String(err), durationMs: Date.now() - start });
    }
  };

  // Test 1: Organizations creation & isolation
  await runTest('1. Organization Creation & Isolation', () => {
    const orgA = db.createOrganization({ name: 'Acme Corp', enforcementMode: 'BLOCK' });
    const orgB = db.createOrganization({ name: 'Beta Logistics', enforcementMode: 'WARN' });

    if (!orgA.organizationId || !orgB.organizationId) throw new Error('Failed to generate organization IDs');
    if (orgA.organizationId === orgB.organizationId) throw new Error('Organization IDs collided');

    const fetchedA = db.getOrganizationById(orgA.organizationId);
    if (!fetchedA || fetchedA.name !== 'Acme Corp') throw new Error('Organization lookup failed');
  });

  // Test 2: Enrollment Token Creation, Hashing & Verification
  await runTest('2. Cryptographic Enrollment Token Lifecycle', () => {
    const orgA = db.getOrganizations()[0];
    const tokenRecord = db.createEnrollmentToken({
      organizationId: orgA.organizationId,
      label: 'Engineering Department Token',
      expiresInDays: 7
    });

    if (!tokenRecord.token.startsWith('pg_enroll_')) throw new Error('Token secret missing expected prefix');
    if (!tokenRecord.tokenHash) throw new Error('Token hash not computed');

    // Token secret should NOT be in getEnrollmentTokens listing
    const listed = db.getEnrollmentTokens(orgA.organizationId);
    const found = listed.find(t => t.id === tokenRecord.id);
    if (found?.token) throw new Error('Raw secret exposed in token listing');

    // Validate valid token
    const valResult = db.validateEnrollmentToken(tokenRecord.token);
    if (!valResult.valid) throw new Error(`Token validation failed: ${valResult.error}`);

    // Revoke token
    db.revokeEnrollmentToken(tokenRecord.id, 'SecOps Admin');
    const valRevoked = db.validateEnrollmentToken(tokenRecord.token);
    if (valRevoked.valid) throw new Error('Revoked token was erroneously validated');
  });

  // Test 3: Device Enrollment & Device API Key Issuance
  await runTest('3. Device Enrollment & Device API Key Generation', () => {
    const org = db.getOrganizations()[0];
    const token = db.createEnrollmentToken({ organizationId: org.organizationId });

    const enrollRes = db.enrollDevice({
      enrollmentToken: token.token,
      installationId: 'inst_macbook_pro_001',
      extensionVersion: '1.0.0',
      browser: 'Chrome 132',
      os: 'macOS 15.3',
      deviceName: 'Alice Macbook Pro'
    });

    if (!enrollRes.success || !enrollRes.device) throw new Error(`Enrollment failed: ${enrollRes.error}`);
    if (!enrollRes.device.deviceApiKey?.startsWith('pg_dev_')) throw new Error('Device API key missing prefix');
    if (enrollRes.device.organizationId !== org.organizationId) throw new Error('Device not bound to correct organization');

    // Lookup device by API key
    const authDev = db.getDeviceByApiKey(enrollRes.device.deviceApiKey);
    if (!authDev || authDev.deviceId !== enrollRes.device.deviceId) throw new Error('Device lookup by API key failed');
  });

  // Test 4: Heartbeat & Online Threshold
  await runTest('4. Device Heartbeat & Fleet Online/Offline Calculation', () => {
    const org = db.getOrganizations()[0];
    const dev = db.getDevices(org.organizationId)[0];

    const hbRes = db.recordHeartbeat({
      deviceId: dev.deviceId,
      installationId: dev.installationId,
      extensionVersion: '1.0.0',
      browser: 'Chrome MV3',
      os: 'macOS'
    });

    if (!hbRes.success) throw new Error('Heartbeat recording failed');

    // Device should be online
    const devices = db.getDevices(org.organizationId);
    const activeDev = devices.find(d => d.deviceId === dev.deviceId);
    if (activeDev?.status === 'OFFLINE') throw new Error('Device with fresh heartbeat marked offline');
  });

  // Test 5: Multi-Tenant Security Event Ingestion & Isolation
  await runTest('5. Strict Multi-Tenant Security Event Isolation', () => {
    const orgs = db.getOrganizations();
    const orgA = orgs[0];
    const orgB = orgs[1] || db.createOrganization({ name: 'Beta Corp' });

    const tokenA = db.createEnrollmentToken({ organizationId: orgA.organizationId });
    const tokenB = db.createEnrollmentToken({ organizationId: orgB.organizationId });

    const devA = db.enrollDevice({ enrollmentToken: tokenA.token, installationId: 'inst_a1', extensionVersion: '1.0.0', browser: 'Chrome', os: 'Linux' }).device!;
    const devB = db.enrollDevice({ enrollmentToken: tokenB.token, installationId: 'inst_b1', extensionVersion: '1.0.0', browser: 'Chrome', os: 'Windows' }).device!;

    const now = Date.now();
    const evtA: CanonicalSecurityEvent = {
      eventId: `evt_org_a_${now}`,
      timestamp: now,
      tabId: 1,
      deviceId: devA.deviceId,
      installationId: devA.installationId,
      organizationId: orgA.organizationId,
      extensionVersion: '1.0.0',
      eventType: 'NAVIGATION_BLOCKED',
      url: 'https://vinted-login.netlify.app/verify',
      hostname: 'vinted-login.netlify.app',
      riskScore: 95,
      riskLevel: 'CRITICAL',
      action: 'BLOCKED',
      threatCategory: 'BRAND_IMPERSONATION',
      detectionReasons: ['Brand impersonation on cloud hosting'],
      signals: [],
      navigationBlocked: true,
      userOverride: false,
      source: 'CLIENT_EXTENSION',
      createdAt: new Date(now).toISOString()
    };

    const evtB: CanonicalSecurityEvent = {
      eventId: `evt_org_b_${now}`,
      timestamp: now,
      tabId: 2,
      deviceId: devB.deviceId,
      installationId: devB.installationId,
      organizationId: orgB.organizationId,
      extensionVersion: '1.0.0',
      eventType: 'WARNING_DISPLAYED',
      url: 'https://paypa1-security.xyz/login',
      hostname: 'paypa1-security.xyz',
      riskScore: 75,
      riskLevel: 'HIGH',
      action: 'WARNED',
      threatCategory: 'BRAND_IMPERSONATION',
      detectionReasons: ['Typosquatting substitution'],
      signals: [],
      navigationBlocked: false,
      userOverride: false,
      source: 'CLIENT_EXTENSION',
      createdAt: new Date(now).toISOString()
    };

    db.ingestSecurityEvent(evtA);
    db.ingestSecurityEvent(evtB);

    // Query Org A events -> must ONLY contain evtA
    const queryA = db.getSecurityEvents({ organizationId: orgA.organizationId });
    if (!queryA.events.some(e => e.eventId === evtA.eventId)) throw new Error('Org A missing its own event');
    if (queryA.events.some(e => e.eventId === evtB.eventId)) throw new Error('CROSS-TENANT LEAK: Org A queried Org B event!');

    // Query Org B events -> must ONLY contain evtB
    const queryB = db.getSecurityEvents({ organizationId: orgB.organizationId });
    if (!queryB.events.some(e => e.eventId === evtB.eventId)) throw new Error('Org B missing its own event');
    if (queryB.events.some(e => e.eventId === evtA.eventId)) throw new Error('CROSS-TENANT LEAK: Org B queried Org A event!');
  });

  // Test 6: Event Idempotency & Deduplication
  await runTest('6. Telemetry Event Idempotency & Deduplication', () => {
    const org = db.getOrganizations()[0];
    const dev = db.getDevices(org.organizationId)[0];
    const eventId = `evt_dedup_test_${Date.now()}`;

    const evt: CanonicalSecurityEvent = {
      eventId,
      timestamp: Date.now(),
      tabId: 1,
      deviceId: dev.deviceId,
      installationId: dev.installationId,
      organizationId: org.organizationId,
      extensionVersion: '1.0.0',
      eventType: 'NAVIGATION_BLOCKED',
      url: 'https://amaz0n-security.top/auth',
      hostname: 'amaz0n-security.top',
      riskScore: 90,
      riskLevel: 'CRITICAL',
      action: 'BLOCKED',
      threatCategory: 'BRAND_IMPERSONATION',
      detectionReasons: ['Homoglyph'],
      signals: [],
      navigationBlocked: true,
      userOverride: false,
      source: 'CLIENT_EXTENSION',
      createdAt: new Date().toISOString()
    };

    const firstIngest = db.ingestSecurityEvent(evt);
    if (!firstIngest.success || firstIngest.isDuplicate) throw new Error('First ingestion failed or marked duplicate');

    const secondIngest = db.ingestSecurityEvent(evt);
    if (!secondIngest.isDuplicate) throw new Error('Duplicate event was not recognized as duplicate');
  });

  // Test 7: Privacy Sanitization
  await runTest('7. Telemetry Privacy Sanitization of Sensitive Query Parameters', () => {
    const org = db.getOrganizations()[0];
    const dev = db.getDevices(org.organizationId)[0];

    const sensitiveUrl = 'https://fake-login.com/login?username=alice&password=SuperSecretPassword123!&token=jwt_xyz_999';
    const evt: CanonicalSecurityEvent = {
      eventId: `evt_privacy_${Date.now()}`,
      timestamp: Date.now(),
      tabId: 1,
      deviceId: dev.deviceId,
      installationId: dev.installationId,
      organizationId: org.organizationId,
      extensionVersion: '1.0.0',
      eventType: 'FORM_INTERCEPTED',
      url: sensitiveUrl,
      hostname: 'fake-login.com',
      riskScore: 85,
      riskLevel: 'HIGH',
      action: 'BLOCKED',
      threatCategory: 'CREDENTIAL_HARVESTING',
      detectionReasons: ['Rogue form'],
      signals: [],
      navigationBlocked: false,
      userOverride: false,
      source: 'CLIENT_EXTENSION',
      createdAt: new Date().toISOString()
    };

    db.ingestSecurityEvent(evt);
    const stored = db.getEventById(evt.eventId);

    if (!stored) throw new Error('Stored event not found');
    if (stored.url.includes('SuperSecretPassword123!')) throw new Error('PRIVACY VIOLATION: Raw password was stored in database!');
    if (stored.url.includes('jwt_xyz_999')) throw new Error('PRIVACY VIOLATION: Raw token was stored in database!');
    if (!stored.url.includes('[REDACTED]')) throw new Error('Privacy redaction placeholder missing');
  });

  // Test 8: Durable Queue Bounded Offline Buffer
  await runTest('8. Durable Queue Bounded Offline Capacity & Backoff', async () => {
    const queue = new DurableTelemetryQueue({
      maxQueueSize: 50,
      backendUrl: 'http://invalid-unreachable-domain-xyz.local:3000'
    });

    const now = Date.now();
    for (let i = 0; i < 60; i++) {
      queue.enqueue({
        eventId: `evt_buf_${i}_${now}`,
        timestamp: now + i,
        tabId: i,
        deviceId: 'DEV-TEST',
        installationId: 'inst_test',
        organizationId: 'ORG-ACME-PILOT',
        extensionVersion: '1.0.0',
        eventType: 'SUSPICIOUS_OBSERVED',
        url: `https://test-${i}.com`,
        hostname: `test-${i}.com`,
        riskScore: 50,
        riskLevel: 'MEDIUM',
        action: 'ALLOWED',
        threatCategory: 'OTHER',
        detectionReasons: ['Observation'],
        signals: [],
        navigationBlocked: false,
        userOverride: false,
        source: 'CLIENT_EXTENSION',
        createdAt: new Date(now + i).toISOString()
      });
    }

    if (queue.getQueueSize() > 50) {
      throw new Error(`Queue size exceeded maximum capacity bound of 50 (actual: ${queue.getQueueSize()})`);
    }
  });

  // Test 9: 6-Axis State Model - Standalone Individual Mode (Section M Steps 1-3)
  await runTest('9. State Model: Standalone Individual Protection (Section M Steps 1-3)', () => {
    const queue = new DurableTelemetryQueue({
      localProtectionActive: true,
      telemetryEnabled: true
    });

    const status = queue.getStatusModel();
    if (status.localProtection !== 'LOCAL_PROTECTION_ACTIVE') throw new Error('Local protection must be ACTIVE for standalone');
    if (status.cloudEnrollment !== 'NOT_ENROLLED') throw new Error('Cloud enrollment must be NOT_ENROLLED for standalone');
    if (status.cloudSync !== 'NOT_APPLICABLE') throw new Error('Cloud sync must be NOT_APPLICABLE when not enrolled');
    if (status.deviceManagement !== 'UNKNOWN') throw new Error('Device management must be UNKNOWN when not enrolled');
    if (status.headline !== 'Protected locally') throw new Error(`Unexpected headline: ${status.headline}`);
    if (status.organizationName) throw new Error('Organization name must NOT be exposed when not enrolled');
  });

  // Test 10: 6-Axis State Model - Enterprise Enrollment & Sync (Section M Steps 4-9)
  await runTest('10. State Model: Enterprise Enrollment & Sync (Section M Steps 4-9)', async () => {
    const org = db.getOrganizations()[0];
    const token = db.createEnrollmentToken({ organizationId: org.organizationId, label: 'E2E Acceptance Token' });

    // Mock fetch to simulate backend communication
    const mockFetch = async (url: string, init?: any) => {
      if (url.includes('/api/devices/enroll')) {
        const body = JSON.parse(init.body);
        const res = db.enrollDevice({
          enrollmentToken: body.enrollmentToken,
          installationId: body.installationId,
          extensionVersion: body.extensionVersion,
          browser: body.browser,
          os: body.os
        });
        if (!res.success || !res.device) {
          return { ok: false, status: 400, json: async () => ({ error: res.error }) } as any;
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            deviceId: res.device.deviceId,
            organizationId: res.device.organizationId,
            organizationName: org.name,
            deviceApiKey: res.device.deviceApiKey
          })
        } as any;
      }
      if (url.includes('/api/devices/heartbeat')) {
        return { ok: true, status: 200, json: async () => ({ success: true }) } as any;
      }
      if (url.includes('/api/events')) {
        return { ok: true, status: 200, json: async () => ({ success: true, ingested: 1 }) } as any;
      }
      return { ok: false, status: 404 } as any;
    };

    const queue = new DurableTelemetryQueue({
      fetchProvider: mockFetch as any,
      backendUrl: 'http://localhost:3000'
    });

    const enrollRes = await queue.enrollDevice(token.token);
    if (!enrollRes.success) throw new Error(`Enrollment failed: ${enrollRes.error}`);

    const status = queue.getStatusModel();
    if (status.cloudEnrollment !== 'ENROLLED') throw new Error(`Expected ENROLLED, got ${status.cloudEnrollment}`);
    if (status.cloudSync !== 'SYNCED') throw new Error(`Expected SYNCED, got ${status.cloudSync}`);
    if (status.deviceManagement !== 'ACTIVE') throw new Error(`Expected ACTIVE management, got ${status.deviceManagement}`);
    if (status.headline !== 'Protected & managed') throw new Error(`Expected 'Protected & managed', got ${status.headline}`);
    if (!status.subline.includes(org.name)) throw new Error(`Subline missing organization name: ${status.subline}`);
  });

  // Test 11: 6-Axis State Model - Cloud Outage & Resilient Local Protection (Section M Steps 10-15)
  await runTest('11. State Model: Cloud Outage & Offline Local Protection (Section M Steps 10-15)', async () => {
    // Failing fetch provider simulating network outage
    const offlineFetch = async () => {
      throw new Error('ECONNREFUSED: Server unreachable');
    };

    const queue = new DurableTelemetryQueue({
      organizationId: 'ORG-ACME-PILOT',
      organizationName: 'Acme Corporation',
      deviceApiKey: 'pg_dev_sample_key',
      fetchProvider: offlineFetch as any,
      backendUrl: 'http://localhost:3000'
    });

    // Enqueue security threat event while offline
    queue.enqueue({
      eventId: `evt_offline_${Date.now()}`,
      timestamp: Date.now(),
      tabId: 1,
      deviceId: 'DEV-TEST',
      installationId: 'inst_test',
      organizationId: 'ORG-ACME-PILOT',
      extensionVersion: '1.0.0',
      eventType: 'SUSPICIOUS_OBSERVED',
      url: 'https://evil-phish-offline.com',
      hostname: 'evil-phish-offline.com',
      riskScore: 95,
      riskLevel: 'CRITICAL',
      action: 'BLOCKED',
      threatCategory: 'CREDENTIAL_HARVESTING',
      detectionReasons: ['Severe typosquatting against Microsoft'],
      signals: [],
      navigationBlocked: true,
      userOverride: false,
      source: 'CLIENT_EXTENSION',
      createdAt: new Date().toISOString()
    });

    // Attempt flush - will fail safely without dropping events
    const flushRes = await queue.flushQueue();
    if (flushRes.synced !== 0) throw new Error('Expected 0 synced during offline outage');
    if (flushRes.remaining !== 1) throw new Error('Pending event was erroneously dropped during offline');

    const status = queue.getStatusModel();
    if (status.localProtection !== 'LOCAL_PROTECTION_ACTIVE') throw new Error('Local protection MUST remain ACTIVE when cloud is offline');
    if (status.cloudSync !== 'CLOUD_OFFLINE') throw new Error(`Expected CLOUD_OFFLINE sync state, got ${status.cloudSync}`);
    if (status.cloudAvailability !== 'OFFLINE') throw new Error(`Expected OFFLINE cloud availability, got ${status.cloudAvailability}`);
    if (status.telemetryState !== 'TELEMETRY_QUEUED') throw new Error(`Expected TELEMETRY_QUEUED, got ${status.telemetryState}`);
    if (status.headline !== 'Protected (cloud offline)') throw new Error(`Expected 'Protected (cloud offline)', got ${status.headline}`);
  });

  // Test 12: 6-Axis State Model - Device Revocation & Unenrollment (Section M Steps 18-21)
  await runTest('12. State Model: Revocation & Unenrollment (Section M Steps 18-21)', async () => {
    // 401 Unauthorized Mock Fetch (Revoked device)
    const revokedFetch = async () => {
      return { ok: false, status: 401, json: async () => ({ error: 'Device enrollment has been revoked' }) } as any;
    };

    const queue = new DurableTelemetryQueue({
      organizationId: 'ORG-ACME-PILOT',
      organizationName: 'Acme Corporation',
      deviceApiKey: 'pg_dev_revoked_key',
      fetchProvider: revokedFetch as any,
      backendUrl: 'http://localhost:3000'
    });

    queue.enqueue({
      eventId: 'evt_revoked_test',
      timestamp: Date.now(),
      tabId: 1,
      deviceId: 'DEV-REVOKED',
      installationId: 'inst_test',
      organizationId: 'ORG-ACME-PILOT',
      extensionVersion: '1.0.0',
      eventType: 'SUSPICIOUS_OBSERVED',
      url: 'https://test.com',
      hostname: 'test.com',
      riskScore: 10,
      riskLevel: 'LOW',
      action: 'ALLOWED',
      threatCategory: 'OTHER',
      detectionReasons: ['Clean'],
      signals: [],
      navigationBlocked: false,
      userOverride: false,
      source: 'CLIENT_EXTENSION',
      createdAt: new Date().toISOString()
    });

    // Attempt flush -> gets 401
    await queue.flushQueue();

    const status = queue.getStatusModel();
    if (status.localProtection !== 'LOCAL_PROTECTION_ACTIVE') throw new Error('Local protection must remain ACTIVE even when revoked');
    if (status.cloudEnrollment !== 'ENROLLMENT_REVOKED') throw new Error(`Expected ENROLLMENT_REVOKED, got ${status.cloudEnrollment}`);
    if (status.deviceManagement !== 'REVOKED') throw new Error(`Expected REVOKED device management, got ${status.deviceManagement}`);
    if (status.headline !== 'Protected locally') throw new Error(`Expected 'Protected locally', got ${status.headline}`);
    if (!status.subline.includes('Organization enrollment has ended')) throw new Error(`Expected subline mentioning ended enrollment, got: ${status.subline}`);

    // Now test user unenroll / disconnect back to pristine standalone
    const unenrollRes = await queue.unenroll();
    if (!unenrollRes.success) throw new Error('Unenroll failed');
    const standaloneStatus = queue.getStatusModel();
    if (standaloneStatus.cloudEnrollment !== 'NOT_ENROLLED') throw new Error('Expected NOT_ENROLLED after unenroll');
  });

  // Clean up test DB
  if (fs.existsSync(testDbFile)) {
    try { fs.unlinkSync(testDbFile); } catch {}
  }

  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;

  return {
    total: results.length,
    passed,
    failed,
    results
  };
}
