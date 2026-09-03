import React, { useState, useEffect } from 'react';
import {
  Shield,
  Save,
  Check,
  AlertTriangle,
  Radio,
  Clock,
  Key,
  Layers,
  Server,
  Copy,
  Plus,
  Trash2,
  Lock
} from 'lucide-react';
import { Organization, EnforcementMode, EnrollmentToken } from '../../core/types';

interface SettingsPoliciesViewProps {
  organization: Organization | null;
  onUpdateOrganization: (updates: Partial<Organization>) => Promise<void>;
}

export const SettingsPoliciesView: React.FC<SettingsPoliciesViewProps> = ({
  organization,
  onUpdateOrganization
}) => {
  const [enforcementMode, setEnforcementMode] = useState<EnforcementMode>(
    organization?.enforcementMode || 'BLOCK'
  );
  const [telemetryEnabled, setTelemetryEnabled] = useState<boolean>(
    organization?.telemetryEnabled ?? true
  );
  const [retentionDays, setRetentionDays] = useState<number>(
    organization?.retentionDays || 90
  );
  const [minExtensionVersion, setMinExtensionVersion] = useState<string>(
    organization?.minExtensionVersion || '1.0.0'
  );
  const [isSaving, setIsSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Tokens state
  const [tokens, setTokens] = useState<EnrollmentToken[]>([]);
  const [newTokenLabel, setNewTokenLabel] = useState('');
  const [copiedToken, setCopiedToken] = useState<string | null>(null);
  const [isGeneratingToken, setIsGeneratingToken] = useState(false);

  useEffect(() => {
    if (organization?.organizationId) {
      fetchTokens();
    }
  }, [organization?.organizationId]);

  const fetchTokens = async () => {
    if (!organization) return;
    try {
      const res = await fetch(`/api/organizations/${organization.organizationId}/tokens`);
      if (res.ok) {
        const data = await res.json();
        setTokens(data.tokens || []);
      }
    } catch {}
  };

  const handleCreateToken = async () => {
    if (!organization) return;
    setIsGeneratingToken(true);
    try {
      const res = await fetch(`/api/organizations/${organization.organizationId}/tokens`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: newTokenLabel.trim() || 'Deployment Pilot Token',
          expiresInDays: 30,
          actor: 'Security Admin Console'
        })
      });
      if (res.ok) {
        setNewTokenLabel('');
        fetchTokens();
      }
    } finally {
      setIsGeneratingToken(false);
    }
  };

  const handleRevokeToken = async (tokenId: string) => {
    try {
      const res = await fetch(`/api/tokens/${tokenId}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ actor: 'Security Admin Console' })
      });
      if (res.ok) {
        fetchTokens();
      }
    } catch {}
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedToken(id);
    setTimeout(() => setCopiedToken(null), 2500);
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await onUpdateOrganization({
        enforcementMode,
        telemetryEnabled,
        retentionDays,
        minExtensionVersion
      });
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 3000);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="max-w-4xl space-y-6">
      {/* Policy Enforcement Level */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
          Fleet Threat Enforcement Mode
        </h3>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          Controls how employee browser extensions respond when a critical phishing or typosquatting destination is detected.
        </p>

        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
          {/* BLOCK */}
          <div
            onClick={() => setEnforcementMode('BLOCK')}
            className={`cursor-pointer rounded-xl border p-4 transition-all ${
              enforcementMode === 'BLOCK'
                ? 'border-blue-600 bg-blue-50/50 dark:border-blue-500 dark:bg-blue-950/30'
                : 'border-slate-200 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/40'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-900 dark:text-slate-100">BLOCK (Standard)</span>
              <span className="flex h-4 w-4 items-center justify-center rounded-full border border-slate-300 dark:border-slate-600">
                {enforcementMode === 'BLOCK' && (
                  <span className="h-2 w-2 rounded-full bg-blue-600 dark:bg-blue-400" />
                )}
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              Immediately intercepts navigations to high-risk & critical threats. Displays PhishGuard warning page.
            </p>
          </div>

          {/* WARN */}
          <div
            onClick={() => setEnforcementMode('WARN')}
            className={`cursor-pointer rounded-xl border p-4 transition-all ${
              enforcementMode === 'WARN'
                ? 'border-blue-600 bg-blue-50/50 dark:border-blue-500 dark:bg-blue-950/30'
                : 'border-slate-200 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/40'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-900 dark:text-slate-100">WARN (Advisory)</span>
              <span className="flex h-4 w-4 items-center justify-center rounded-full border border-slate-300 dark:border-slate-600">
                {enforcementMode === 'WARN' && (
                  <span className="h-2 w-2 rounded-full bg-blue-600 dark:bg-blue-400" />
                )}
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              Displays prominent in-page advisory banner without hard navigation termination.
            </p>
          </div>

          {/* MONITOR */}
          <div
            onClick={() => setEnforcementMode('MONITOR')}
            className={`cursor-pointer rounded-xl border p-4 transition-all ${
              enforcementMode === 'MONITOR'
                ? 'border-blue-600 bg-blue-50/50 dark:border-blue-500 dark:bg-blue-950/30'
                : 'border-slate-200 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/40'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-900 dark:text-slate-100">MONITOR (Audit)</span>
              <span className="flex h-4 w-4 items-center justify-center rounded-full border border-slate-300 dark:border-slate-600">
                {enforcementMode === 'MONITOR' && (
                  <span className="h-2 w-2 rounded-full bg-blue-600 dark:bg-blue-400" />
                )}
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              Silently records security telemetry events without alerting or interrupting employee workflows.
            </p>
          </div>
        </div>
      </div>

      {/* Organization Enrollment Tokens */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
              Device Enrollment Tokens
            </h3>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              Tokens are deployed via Chrome Managed Storage (GPO / Workspace) to enroll employee browser instances.
            </p>
          </div>
        </div>

        {/* Generate Token Input */}
        <div className="mt-4 flex gap-2">
          <input
            type="text"
            placeholder="Token Label (e.g. Sales Team Pilot)"
            value={newTokenLabel}
            onChange={(e) => setNewTokenLabel(e.target.value)}
            className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-slate-900 focus:border-blue-500 focus:outline-hidden dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
          />
          <button
            onClick={handleCreateToken}
            disabled={isGeneratingToken}
            className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" />
            Generate Enrollment Token
          </button>
        </div>

        {/* Active Tokens List */}
        <div className="mt-4 divide-y divide-slate-100 border-t border-slate-100 dark:divide-slate-800 dark:border-slate-800">
          {tokens.map((t) => (
            <div key={t.tokenId} className="flex items-center justify-between py-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">{t.label}</span>
                  {t.revoked ? (
                    <span className="rounded-sm bg-red-100 px-1.5 py-0.5 text-[10px] font-bold text-red-700 dark:bg-red-950/50 dark:text-red-400">REVOKED</span>
                  ) : (
                    <span className="rounded-sm bg-emerald-100 px-1.5 py-0.5 text-[10px] font-bold text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-400">ACTIVE</span>
                  )}
                </div>
                <div className="flex items-center gap-2 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                  <span>Token: {t.token ? `${t.token.slice(0, 14)}...` : `Hash: ${t.tokenHash.slice(0, 12)}...`}</span>
                  <span>• Uses: {t.useCount}</span>
                  <span>• Created: {new Date(t.createdAt).toLocaleDateString()}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {t.token && !t.revoked && (
                  <button
                    onClick={() => copyToClipboard(t.token!, t.tokenId)}
                    className="flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-800"
                  >
                    <Copy className="h-3 w-3" />
                    {copiedToken === t.tokenId ? 'Copied' : 'Copy'}
                  </button>
                )}
                {!t.revoked && (
                  <button
                    onClick={() => handleRevokeToken(t.tokenId)}
                    className="flex items-center gap-1 rounded-md border border-red-200 px-2.5 py-1 text-[11px] font-medium text-red-600 hover:bg-red-50 dark:border-red-900/50 dark:text-red-400 dark:hover:bg-red-950/50"
                  >
                    <Trash2 className="h-3 w-3" />
                    Revoke
                  </button>
                )}
              </div>
            </div>
          ))}
          {tokens.length === 0 && (
            <div className="py-4 text-center text-xs text-slate-500">
              No enrollment tokens created yet.
            </div>
          )}
        </div>
      </div>

      {/* Fleet Version Policy */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
          Agent Version Compliance
        </h3>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          Enforce minimum extension version across all enrolled endpoints.
        </p>

        <div className="mt-4 flex max-w-sm items-center gap-3">
          <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
            Minimum Version:
          </label>
          <input
            type="text"
            value={minExtensionVersion}
            onChange={(e) => setMinExtensionVersion(e.target.value)}
            className="w-32 rounded-lg border border-slate-200 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-blue-500 focus:outline-hidden dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100"
          />
        </div>
      </div>

      {/* Data Retention & Privacy Settings */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
          Telemetry & Data Retention Policy
        </h3>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          Control event storage limits and privacy-preserving synchronization.
        </p>

        <div className="mt-4 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                Centralized Telemetry Synchronization
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400">
                Allow connected extensions to transmit anonymized CanonicalSecurityEvent logs to backend.
              </div>
            </div>
            <input
              type="checkbox"
              checked={telemetryEnabled}
              onChange={(e) => setTelemetryEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
            />
          </div>

          <div className="flex items-center justify-between border-t border-slate-100 pt-4 dark:border-slate-800">
            <div>
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                Historical Event Retention Window
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400">
                Automatically purge telemetry events older than the specified retention window.
              </div>
            </div>
            <select
              value={retentionDays}
              onChange={(e) => setRetentionDays(parseInt(e.target.value, 10))}
              className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300"
            >
              <option value={30}>30 Days</option>
              <option value={60}>60 Days</option>
              <option value={90}>90 Days (Recommended)</option>
              <option value={180}>180 Days</option>
              <option value={365}>365 Days</option>
            </select>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex items-center justify-end gap-3">
        {savedSuccess && (
          <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-600 dark:text-emerald-400">
            <Check className="h-4 w-4" />
            Policy changes saved & audit log recorded!
          </span>
        )}
        <button
          onClick={handleSave}
          disabled={isSaving}
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-xs font-semibold text-white shadow-xs hover:bg-blue-700 disabled:opacity-50"
        >
          <Save className="h-4 w-4" />
          {isSaving ? 'Saving...' : 'Save Organization Policy'}
        </button>
      </div>
    </div>
  );
};
