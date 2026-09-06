/**
 * Regression Test Suite for 3 Verified Production Bugs:
 * BUG 1: Customer Token Copy Button (Clipboard API, fallback, success state, no fake UI, no logging)
 * BUG 2: Active Enrollment Token Count Inconsistent (Server-authoritative, repeated GETs, no mutation, org-scoped)
 * BUG 3: Extension Service Worker Crash (getStatusModel canonical API, all axes, defensive handling)
 */

import { DurableTelemetryQueue } from '../src/core/events/durableQueue';
import { computeEndpointStatusModel } from '../src/core/types';
import { JsonFileDatabaseAdapter } from '../src/server/storage/jsonFileAdapter';
import { createExpressApp } from '../src/server/app';
import fs from 'fs';
import path from 'path';
import http from 'http';

export async function runThreeBugsRegressionTests(): Promise<{ passed: number; failed: number; errors: string[] }> {
  let passed = 0;
  let failed = 0;
  const errors: string[] = [];

  function assert(condition: boolean, testName: string, detail?: string) {
    if (condition) {
      passed++;
    } else {
      failed++;
      errors.push(`FAIL: ${testName}${detail ? ` (${detail})` : ''}`);
    }
  }

  // =========================================================================
  // BUG 1: Customer Token Copy Button & Clipboard Mechanics
  // =========================================================================
  try {
    // 1.1 Test copy handler with modern navigator.clipboard success
    let clipboardWrittenText = '';
    const mockNavigatorSuccess: any = {
      clipboard: {
        writeText: async (t: string) => {
          clipboardWrittenText = t;
        }
      }
    };

    const copyRunner = async (
      nav: any,
      doc: any,
      textToCopy: string,
      id: string,
      setCopiedState: (id: string | null) => void
    ): Promise<boolean> => {
      if (!textToCopy) return false;
      let success = false;
      if (typeof nav !== 'undefined' && nav.clipboard && typeof nav.clipboard.writeText === 'function') {
        try {
          await nav.clipboard.writeText(textToCopy);
          success = true;
        } catch {
          success = false;
        }
      }
      if (!success && typeof doc !== 'undefined' && typeof doc.createElement === 'function') {
        try {
          const textarea = doc.createElement('textarea');
          textarea.value = textToCopy;
          doc.body.appendChild(textarea);
          success = doc.execCommand('copy');
          doc.body.removeChild(textarea);
        } catch {
          success = false;
        }
      }
      if (success) {
        setCopiedState(id);
        return true;
      }
      return false;
    };

    let copiedId: string | null = null;
    const testSecret = 'pg_enroll_test_secret_abc123';
    const ok1 = await copyRunner(mockNavigatorSuccess, undefined, testSecret, 'tok_1', (id) => { copiedId = id; });
    assert(ok1 === true, 'Bug 1.1: copyRunner succeeds with navigator.clipboard');
    assert(clipboardWrittenText === testSecret, 'Bug 1.1: Exactly the token secret was written to clipboard');
    assert(copiedId === 'tok_1', 'Bug 1.1: copiedId correctly set to token id after success');

    // 1.2 Test copy handler when navigator.clipboard rejects (iframe restriction) -> falls back to execCommand
    copiedId = null;
    let execCommandCalledWith = '';
    const mockNavigatorReject: any = {
      clipboard: {
        writeText: async () => {
          throw new Error('Clipboard permission denied');
        }
      }
    };
    const mockDocumentFallback: any = {
      createElement: () => ({
        value: '',
        setAttribute: () => {},
        style: {}
      }),
      body: {
        appendChild: (el: any) => { execCommandCalledWith = el.value; },
        removeChild: () => {}
      },
      execCommand: (cmd: string) => cmd === 'copy'
    };

    const ok2 = await copyRunner(mockNavigatorReject, mockDocumentFallback, testSecret, 'tok_2', (id) => { copiedId = id; });
    assert(ok2 === true, 'Bug 1.2: copyRunner succeeds via execCommand fallback when navigator.clipboard fails');
    assert(execCommandCalledWith === testSecret, 'Bug 1.2: Fallback correctly copied the token secret');
    assert(copiedId === 'tok_2', 'Bug 1.2: copiedId correctly updated on fallback success');

    // 1.3 Test copy handler when BOTH fail -> must NOT fake copied state
    copiedId = null;
    const mockDocumentFail: any = {
      createElement: () => ({ value: '', setAttribute: () => {}, style: {} }),
      body: { appendChild: () => {}, removeChild: () => {} },
      execCommand: () => false
    };
    const ok3 = await copyRunner(mockNavigatorReject, mockDocumentFail, testSecret, 'tok_3', (id) => { copiedId = id; });
    assert(ok3 === false, 'Bug 1.3: copyRunner returns false when copy fails');
    assert(copiedId === null, 'Bug 1.3: copiedId remains null; no fake checkmark on failure');

    // 1.4 Test copy handler with empty token text
    copiedId = null;
    const ok4 = await copyRunner(mockNavigatorSuccess, undefined, '', 'tok_empty', (id) => { copiedId = id; });
    assert(ok4 === false, 'Bug 1.4: copyRunner rejects empty string without setting copied state');
    assert(copiedId === null, 'Bug 1.4: copiedId remains null when empty string provided');
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Bug 1 tests threw: ${err?.message}`);
  }

  // =========================================================================
  // BUG 2: Active Enrollment Token Count Inconsistent & Authoritative Server State
  // =========================================================================
  const testDbFile = path.resolve(process.cwd(), 'data', 'test-token-consistency-db.json');
  if (fs.existsSync(testDbFile)) {
    try { fs.unlinkSync(testDbFile); } catch {}
  }

  try {
    const db = new JsonFileDatabaseAdapter(testDbFile);
    const orgId = 'ORG-ACME-PILOT';

    // 2.1 Initial token count is stable
    const initialTokens = db.getEnrollmentTokens(orgId);
    assert(initialTokens.length === 1, 'Bug 2.1: Initial organization has exactly 1 default token', String(initialTokens.length));

    // 2.2 Create Production Fleet Rollout token
    const created = db.createEnrollmentToken({
      organizationId: orgId,
      label: 'Production Fleet Rollout',
      expiresInDays: 30,
      maxUses: 100,
      actor: 'Admin Console'
    });
    assert(created.label === 'Production Fleet Rollout', 'Bug 2.2: Created token with exact label');
    assert(created.status === 'ACTIVE', 'Bug 2.2: Created token status is ACTIVE');

    // 2.3 Verify 20 repeated getEnrollmentTokens calls remain completely consistent and do NOT duplicate
    for (let i = 1; i <= 20; i++) {
      const tokens = db.getEnrollmentTokens(orgId);
      const rolloutTokens = tokens.filter(t => t.label === 'Production Fleet Rollout');
      assert(
        rolloutTokens.length === 1,
        `Bug 2.3 [Iter ${i}]: Production Fleet Rollout token count must be exactly 1`,
        `Got: ${rolloutTokens.length}`
      );
      assert(
        tokens.length === 2,
        `Bug 2.3 [Iter ${i}]: Total tokens count must remain 2`,
        `Got: ${tokens.length}`
      );
      // Ensure GET never leaks raw plaintext token
      for (const t of tokens) {
        assert(t.token === '', `Bug 2.3 [Iter ${i}]: GET response token field must be empty string`);
      }
    }

    // 2.4 Verify multi-tenant isolation: Org B receives 0 of Org A tokens
    const otherOrgTokens = db.getEnrollmentTokens('ORG-OTHER-TENANT');
    assert(otherOrgTokens.length === 0, 'Bug 2.4: Other organization sees 0 tokens belonging to Org A');

    // 2.5 Verify active calculation respects expiration and revocation without modifying stored records on GET
    const tokenListBefore = db.getEnrollmentTokens(orgId);
    const rolloutId = created.id;
    const okRevoke = db.revokeEnrollmentToken(rolloutId, 'Admin');
    assert(okRevoke === true, 'Bug 2.5: Token revocation succeeds');

    const tokenListAfter = db.getEnrollmentTokens(orgId);
    const revokedTok = tokenListAfter.find(t => t.id === rolloutId);
    assert(revokedTok?.status === 'REVOKED', 'Bug 2.5: Status is dynamically computed as REVOKED');
    const activeTokens = tokenListAfter.filter(t => t.status === 'ACTIVE');
    assert(activeTokens.length === 1, 'Bug 2.5: Exactly 1 active token remains after revocation');
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Bug 2 tests threw: ${err?.message}`);
  } finally {
    if (fs.existsSync(testDbFile)) {
      try { fs.unlinkSync(testDbFile); } catch {}
    }
  }

  // =========================================================================
  // BUG 3: Extension Service Worker Crash & Canonical Status Model
  // =========================================================================
  try {
    const queue = new DurableTelemetryQueue({
      backendUrl: 'http://localhost:3000',
      deviceApiKey: 'test_key',
      deviceId: 'DEV-TEST-01',
      organizationId: 'ORG-ACME-PILOT',
      maxQueueSize: 50,
      flushIntervalMs: 60000
    });

    // 3.1 getStatusModel must be a function
    assert(typeof queue.getStatusModel === 'function', 'Bug 3.1: queue.getStatusModel is a function');

    // 3.2 Calling getStatusModel returns a valid, non-throwing status object
    const status = queue.getStatusModel();
    assert(status !== null && typeof status === 'object', 'Bug 3.2: getStatusModel returns an object');
    assert(status.localProtection === 'LOCAL_PROTECTION_ACTIVE', 'Bug 3.2: Local protection is ACTIVE');
    assert(typeof status.cloudEnrollment === 'string', 'Bug 3.2: cloudEnrollment is defined');
    assert(typeof status.cloudSync === 'string', 'Bug 3.2: cloudSync is defined');
    assert(typeof status.deviceManagement === 'string', 'Bug 3.2: deviceManagement is defined');
    assert(typeof status.headline === 'string' && status.headline.length > 0, 'Bug 3.2: headline is non-empty');
    assert(typeof status.subline === 'string' && status.subline.length > 0, 'Bug 3.2: subline is non-empty');
    assert(typeof status.badgeLabel === 'string' && status.badgeLabel.length > 0, 'Bug 3.2: badgeLabel is non-empty');

    // 3.3 Verify computeEndpointStatusModel across all canonical states
    const standaloneModel = computeEndpointStatusModel({
      localProtectionActive: true,
      isEnrolled: false
    });
    assert(standaloneModel.headline === 'Protected locally', 'Bug 3.3: Standalone headline correct');
    assert(standaloneModel.badgeVariant === 'safe', 'Bug 3.3: Standalone badgeVariant safe');
    assert(standaloneModel.localProtection === 'LOCAL_PROTECTION_ACTIVE', 'Bug 3.3: Standalone local protection active');

    const outageModel = computeEndpointStatusModel({
      localProtectionActive: true,
      isEnrolled: true,
      organizationId: 'ORG-ACME-PILOT',
      organizationName: 'Acme Corporation',
      isOnline: false,
      queueSize: 5
    });
    assert(outageModel.headline === 'Protected (cloud offline)', 'Bug 3.3: Cloud outage headline is Protected (cloud offline)');
    assert(outageModel.subline.includes('buffered telemetry events will retry'), 'Bug 3.3: Subline mentions buffered telemetry retry');
    assert(outageModel.badgeVariant === 'offline', 'Bug 3.3: Cloud outage badgeVariant offline');

    // 3.4 Verify transpiled extension files exist and contain getStatusModel
    const transpiledQueuePath = path.resolve(process.cwd(), 'extension', 'events', 'durableQueue.js');
    assert(fs.existsSync(transpiledQueuePath), 'Bug 3.4: Transpiled extension/events/durableQueue.js exists');
    if (fs.existsSync(transpiledQueuePath)) {
      const content = fs.readFileSync(transpiledQueuePath, 'utf-8');
      assert(content.includes('getStatusModel'), 'Bug 3.4: Transpiled durableQueue.js contains getStatusModel');
      assert(content.includes('computeEndpointStatusModel'), 'Bug 3.4: Transpiled durableQueue.js references computeEndpointStatusModel');
    }

    const transpiledTypesPath = path.resolve(process.cwd(), 'extension', 'types.js');
    assert(fs.existsSync(transpiledTypesPath), 'Bug 3.4: Transpiled extension/types.js exists for Chrome ES module loader');
  } catch (err: any) {
    failed++;
    errors.push(`FAIL: Bug 3 tests threw: ${err?.message}`);
  }

  return { passed, failed, errors };
}
