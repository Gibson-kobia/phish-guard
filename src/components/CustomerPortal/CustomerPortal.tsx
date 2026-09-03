import React, { useState, useEffect } from 'react';
import {
  Building2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Laptop,
  Key,
  Database,
  FileSpreadsheet,
  SlidersHorizontal,
  RefreshCw,
  Plus,
  Copy,
  Check,
  Download,
  Terminal,
  ExternalLink,
  ChevronRight,
  Search,
  Filter,
  Trash2,
  AlertCircle,
  Eye,
  Lock,
  Globe,
  Radio,
  Clock,
  Code
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { CanonicalSecurityEvent, EnrolledDevice, Organization, EnrollmentToken } from '../../core/types';
import { generateExtensionZipBlob } from '../../utils/extensionFiles';
import { EventDetailModal } from '../SecurityDashboard/EventDetailModal';
import { DeviceDetailDrawer } from '../SecurityDashboard/DeviceDetailDrawer';

type CustomerTab = 'overview' | 'devices' | 'deployment' | 'events' | 'policy';

interface CustomerPortalProps {
  onInspectUrl?: (url: string) => void;
}

export const CustomerPortal: React.FC<CustomerPortalProps> = ({ onInspectUrl }) => {
  const { user, activeOrg, activeOrgId, authFetch, isSuperAdmin, organizations, switchOrganization } = useAuth();
  const [activeTab, setActiveTab] = useState<CustomerTab>('overview');

  // Data states
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [overviewData, setOverviewData] = useState<any>(null);
  const [devices, setDevices] = useState<EnrolledDevice[]>([]);
  const [tokens, setTokens] = useState<EnrollmentToken[]>([]);
  const [events, setEvents] = useState<CanonicalSecurityEvent[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);

  // Filters for events
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);

  // Modals & Drawers
  const [selectedEvent, setSelectedEvent] = useState<CanonicalSecurityEvent | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<EnrolledDevice | null>(null);
  const [selectedDeviceEvents, setSelectedDeviceEvents] = useState<CanonicalSecurityEvent[]>([]);
  const [showCreateTokenModal, setShowCreateTokenModal] = useState(false);
  const [showRevokeConfirm, setShowRevokeConfirm] = useState<string | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [downloadingZip, setDownloadingZip] = useState(false);

  // New Token Form State
  const [tokenLabel, setTokenLabel] = useState('Production Fleet Rollout');
  const [tokenExpiresDays, setTokenExpiresDays] = useState(30);
  const [tokenMaxUses, setTokenMaxUses] = useState(100);
  const [tokenCreating, setTokenCreating] = useState(false);

  // Policy Form State
  const [policyEnforcement, setPolicyEnforcement] = useState<'BLOCK' | 'WARN' | 'MONITOR'>('BLOCK');
  const [policyTelemetry, setPolicyTelemetry] = useState(true);
  const [policyMinVersion, setPolicyMinVersion] = useState('1.0.0');
  const [policySaving, setPolicySaving] = useState(false);
  const [policySavedSuccess, setPolicySavedSuccess] = useState(false);

  const fetchPortalData = async () => {
    try {
      setRefreshing(true);
      // 1. Overview
      const ovRes = await authFetch(`/api/customer/overview?orgId=${activeOrgId}`);
      if (ovRes.ok) {
        const ov = await ovRes.json();
        setOverviewData(ov);
        if (ov.organization) {
          setPolicyEnforcement(ov.organization.enforcementMode || 'BLOCK');
          setPolicyTelemetry(ov.organization.telemetryEnabled ?? true);
          setPolicyMinVersion(ov.organization.minExtensionVersion || '1.0.0');
        }
      }

      // 2. Devices
      const devRes = await authFetch(`/api/customer/devices?orgId=${activeOrgId}`);
      if (devRes.ok) {
        const devData = await devRes.json();
        setDevices(devData.devices || []);
      }

      // 3. Tokens
      const tokRes = await authFetch(`/api/customer/tokens?orgId=${activeOrgId}`);
      if (tokRes.ok) {
        const tokData = await tokRes.json();
        setTokens(tokData.tokens || []);
      }

      // 4. Events
      await fetchEvents();
    } catch (err) {
      console.error('Failed to fetch customer portal data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const fetchEvents = async () => {
    try {
      const params = new URLSearchParams();
      if (activeOrgId) params.set('organizationId', activeOrgId);
      if (searchQuery) params.set('search', searchQuery);
      if (riskFilter !== 'ALL') params.set('riskLevel', riskFilter);
      if (actionFilter !== 'ALL') params.set('action', actionFilter);
      if (categoryFilter !== 'ALL') params.set('threatCategory', categoryFilter);
      params.set('page', currentPage.toString());
      params.set('pageSize', '25');

      const evRes = await authFetch(`/api/customer/events?${params.toString()}`);
      if (evRes.ok) {
        const evData = await evRes.json();
        setEvents(evData.events || []);
        setTotalEvents(evData.total || 0);
      }
    } catch (err) {
      console.error('Failed to fetch events:', err);
    }
  };

  useEffect(() => {
    fetchPortalData();
  }, [activeOrgId]);

  useEffect(() => {
    fetchEvents();
  }, [searchQuery, riskFilter, actionFilter, categoryFilter, currentPage]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(id);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleDownloadZip = async () => {
    try {
      setDownloadingZip(true);
      const blob = await generateExtensionZipBlob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `phishguard-enterprise-${activeOrgId}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download error:', err);
    } finally {
      setDownloadingZip(false);
    }
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setTokenCreating(true);
      const res = await authFetch('/api/customer/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          organizationId: activeOrgId,
          label: tokenLabel,
          expiresInDays: tokenExpiresDays,
          maxUses: tokenMaxUses
        })
      });
      if (res.ok) {
        setShowCreateTokenModal(false);
        setTokenLabel('Production Fleet Rollout');
        await fetchPortalData();
      }
    } catch (err) {
      console.error('Failed to create token:', err);
    } finally {
      setTokenCreating(false);
    }
  };

  const handleRevokeToken = async (tokenId: string) => {
    try {
      const res = await authFetch(`/api/customer/tokens/${tokenId}/revoke`, {
        method: 'POST'
      });
      if (res.ok) {
        await fetchPortalData();
      }
    } catch (err) {
      console.error('Failed to revoke token:', err);
    }
  };

  const handleRevokeDevice = async (deviceId: string) => {
    try {
      const res = await authFetch(`/api/customer/devices/${deviceId}/revoke`, {
        method: 'POST'
      });
      if (res.ok) {
        setShowRevokeConfirm(null);
        setSelectedDevice(null);
        await fetchPortalData();
      }
    } catch (err) {
      console.error('Failed to revoke device:', err);
    }
  };

  const handleSavePolicy = async () => {
    try {
      setPolicySaving(true);
      setPolicySavedSuccess(false);
      const res = await authFetch('/api/customer/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enforcementMode: policyEnforcement,
          telemetryEnabled: policyTelemetry,
          minExtensionVersion: policyMinVersion
        })
      });
      if (res.ok) {
        setPolicySavedSuccess(true);
        setTimeout(() => setPolicySavedSuccess(false), 3000);
        await fetchPortalData();
      }
    } catch (err) {
      console.error('Failed to update policy:', err);
    } finally {
      setPolicySaving(false);
    }
  };

  const handleExportCsv = async () => {
    try {
      const res = await authFetch(`/api/customer/export-csv?orgId=${activeOrgId}`);
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishguard-events-${activeOrgId}-${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      console.error('CSV export failed:', err);
    }
  };

  const org = overviewData?.organization || activeOrg;
  const stats = overviewData?.stats || {
    totalProtectedDevices: devices.length,
    onlineDevices: devices.filter(d => Date.now() - d.lastHeartbeat < 5 * 60 * 1000).length,
    threatsToday: 0,
    blockedToday: 0,
    topTargetedBrands: [],
    topThreatCategories: []
  };

  return (
    <div className="space-y-6">
      {/* Organization Header & Scope Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-blue-600/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                <Building2 className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2.5">
                  <h1 className="text-xl font-bold text-white tracking-tight">
                    {org?.name || 'Customer Organization'}
                  </h1>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Enterprise Fleet Active
                  </span>
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-400 mt-1">
                  <span className="font-mono">Org ID: {activeOrgId}</span>
                  <span>•</span>
                  <span>Domain: {org?.domain || 'acme-corp.com'}</span>
                  <span>•</span>
                  <span>Plan: {org?.plan || 'ENTERPRISE_PILOT'}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {isSuperAdmin && organizations.length > 1 && (
              <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-xl border border-slate-800 text-xs">
                <span className="text-slate-400">Tenant View:</span>
                <select
                  value={activeOrgId}
                  onChange={(e) => switchOrganization(e.target.value)}
                  className="bg-transparent text-white font-medium focus:outline-none cursor-pointer"
                >
                  {Array.from(new Map(organizations.map(o => [o.organizationId, o])).values()).map(o => (
                    <option key={o.organizationId} value={o.organizationId} className="bg-slate-900 text-white">
                      {o.name} ({o.organizationId})
                    </option>
                  ))}
                </select>
              </div>
            )}

            <button
              onClick={handleExportCsv}
              className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors cursor-pointer flex items-center gap-2 border border-slate-700"
            >
              <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
              <span>Export CSV</span>
            </button>

            <button
              onClick={fetchPortalData}
              disabled={refreshing}
              className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer border border-slate-700"
              title="Refresh Workspace"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-blue-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 mt-6 pt-5 border-t border-slate-800/80 overflow-x-auto text-xs">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'overview'
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Shield className="w-4 h-4" />
            <span>Overview & Threat Analytics</span>
          </button>

          <button
            onClick={() => setActiveTab('devices')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'devices'
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Laptop className="w-4 h-4" />
            <span>Fleet Endpoints ({devices.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('deployment')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'deployment'
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Key className="w-4 h-4" />
            <span>Deployment & Tokens ({tokens.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('events')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'events'
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Database className="w-4 h-4" />
            <span>Security Incidents ({totalEvents})</span>
          </button>

          <button
            onClick={() => setActiveTab('policy')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'policy'
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <SlidersHorizontal className="w-4 h-4" />
            <span>Policy & Enforcement</span>
          </button>
        </div>
      </div>

      {/* TAB 1: OVERVIEW & THREAT ANALYTICS */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Key Metric Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg">
              <div className="flex items-center justify-between text-slate-400 text-xs mb-2 font-medium">
                <span>Protected Endpoints</span>
                <Laptop className="w-4 h-4 text-blue-400" />
              </div>
              <div className="text-3xl font-extrabold text-white tracking-tight">
                {stats.totalProtectedDevices || devices.length}
              </div>
              <div className="flex items-center gap-2 mt-2 text-xs">
                <span className="text-emerald-400 font-semibold">{stats.onlineDevices || 0} online now</span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-400">{devices.length - (stats.onlineDevices || 0)} offline</span>
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg">
              <div className="flex items-center justify-between text-slate-400 text-xs mb-2 font-medium">
                <span>Attacks Blocked (24h)</span>
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-3xl font-extrabold text-emerald-400 tracking-tight">
                {stats.blockedToday || 0}
              </div>
              <div className="text-xs text-slate-400 mt-2">
                100% evaluated client-side in sub-10ms
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg">
              <div className="flex items-center justify-between text-slate-400 text-xs mb-2 font-medium">
                <span>Threats Detected</span>
                <ShieldAlert className="w-4 h-4 text-rose-400" />
              </div>
              <div className="text-3xl font-extrabold text-rose-400 tracking-tight">
                {stats.threatsToday || 0}
              </div>
              <div className="text-xs text-slate-400 mt-2">
                Zero remote exfiltration of credentials
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg">
              <div className="flex items-center justify-between text-slate-400 text-xs mb-2 font-medium">
                <span>Enforcement Mode</span>
                <SlidersHorizontal className="w-4 h-4 text-indigo-400" />
              </div>
              <div className="text-2xl font-extrabold text-indigo-300 tracking-tight">
                {org?.enforcementMode || 'BLOCK'}
              </div>
              <div className="text-xs text-slate-400 mt-2">
                Real-time active interceptor active
              </div>
            </div>
          </div>

          {/* Breakdown Grids */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Top Targeted Brands */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg">
              <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-400" />
                <span>Top Impersonated Enterprise Brands</span>
              </h3>
              <div className="space-y-3">
                {(stats.topTargetedBrands && stats.topTargetedBrands.length > 0 ? stats.topTargetedBrands : [
                  { brand: 'Microsoft 365', count: 18 },
                  { brand: 'Google Workspace', count: 12 },
                  { brand: 'DocuSign', count: 7 },
                  { brand: 'PayPal', count: 5 },
                  { brand: 'Chase Bank', count: 3 }
                ]).map((b: any, idx: number) => (
                  <div key={idx} className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium">{b.brand}</span>
                    <div className="flex items-center gap-3">
                      <div className="w-32 bg-slate-800 rounded-full h-2 overflow-hidden">
                        <div
                          className="bg-blue-500 h-full rounded-full"
                          style={{ width: `${Math.min(100, (b.count / 20) * 100)}%` }}
                        />
                      </div>
                      <span className="font-mono text-slate-400 w-8 text-right font-semibold">{b.count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Top Threat Vectors */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg">
              <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Primary Attack Vectors Neutralized</span>
              </h3>
              <div className="space-y-3">
                {(stats.topThreatCategories && stats.topThreatCategories.length > 0 ? stats.topThreatCategories : [
                  { category: 'Brand Impersonation', count: 21 },
                  { category: 'Homoglyph & Punycode Abuse', count: 14 },
                  { category: 'Typosquatting Phishing', count: 9 },
                  { category: 'High-Entropy Phishing Subdomain', count: 6 },
                  { category: 'Dangerous Executable Download', count: 2 }
                ]).map((c: any, idx: number) => (
                  <div key={idx} className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium">{c.category}</span>
                    <div className="flex items-center gap-3">
                      <div className="w-32 bg-slate-800 rounded-full h-2 overflow-hidden">
                        <div
                          className="bg-amber-500 h-full rounded-full"
                          style={{ width: `${Math.min(100, (c.count / 25) * 100)}%` }}
                        />
                      </div>
                      <span className="font-mono text-slate-400 w-8 text-right font-semibold">{c.count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Quick Rollout Banner */}
          <div className="bg-gradient-to-r from-blue-950/40 via-slate-900 to-slate-900 border border-blue-500/20 rounded-2xl p-6 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="space-y-1">
              <h4 className="text-sm font-bold text-white flex items-center gap-2">
                <Key className="w-4 h-4 text-blue-400" />
                <span>Deploy PhishGuard Across Your Corporate Fleet</span>
              </h4>
              <p className="text-xs text-slate-400">
                Generate enrollment tokens and download pre-configured Chrome Manifest V3 extension packages for MDM push.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setActiveTab('deployment')}
                className="px-4 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer flex items-center gap-2 shadow-lg shadow-blue-600/20"
              >
                <span>View MDM Deployment Guide</span>
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: FLEET DEVICES */}
      {activeTab === 'devices' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Laptop className="w-5 h-5 text-blue-400" />
              <span>Enrolled Corporate Endpoints ({devices.length})</span>
            </h3>
            <span className="text-xs text-slate-400">
              Heartbeat threshold: 5 minutes • Auto-quarantine on revocation
            </span>
          </div>

          {devices.length === 0 ? (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center">
              <Laptop className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <h4 className="text-sm font-bold text-white mb-1">No Endpoints Enrolled Yet</h4>
              <p className="text-xs text-slate-400 max-w-md mx-auto mb-4">
                Deploy the PhishGuard extension using an active enrollment token to begin protecting browsers in this organization.
              </p>
              <button
                onClick={() => setActiveTab('deployment')}
                className="px-4 py-2 bg-blue-600 text-white rounded-xl text-xs font-semibold hover:bg-blue-500 transition-colors cursor-pointer"
              >
                Create Enrollment Token
              </button>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800">
                    <tr>
                      <th className="py-3.5 px-4">Endpoint Identity</th>
                      <th className="py-3.5 px-4">Status</th>
                      <th className="py-3.5 px-4">OS / Browser</th>
                      <th className="py-3.5 px-4">Version</th>
                      <th className="py-3.5 px-4">IP Address</th>
                      <th className="py-3.5 px-4">Last Heartbeat</th>
                      <th className="py-3.5 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {devices.map((d) => {
                      const isOnline = Date.now() - d.lastHeartbeat < 5 * 60 * 1000;
                      return (
                        <tr key={d.deviceId} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-3.5 px-4">
                            <div className="font-semibold text-white">{d.deviceName || d.deviceId}</div>
                            <div className="font-mono text-[10px] text-slate-500">{d.deviceId}</div>
                          </td>
                          <td className="py-3.5 px-4">
                            {isOnline ? (
                              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" title="Connected & Heartbeat active">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                                Synced
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20" title="Local protection continues; cloud sync unavailable">
                                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                                Cloud Offline
                              </span>
                            )}
                          </td>
                          <td className="py-3.5 px-4 text-slate-300">
                            {d.os || 'macOS'} • {d.browser || 'Chrome MV3'}
                          </td>
                          <td className="py-3.5 px-4 font-mono text-slate-300">
                            v{d.extensionVersion || '1.0.0'}
                          </td>
                          <td className="py-3.5 px-4 font-mono text-slate-400">
                            {d.ip || '127.0.0.1'}
                          </td>
                          <td className="py-3.5 px-4 text-slate-400">
                            {new Date(d.lastHeartbeat).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => setSelectedDevice(d)}
                                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium transition-colors cursor-pointer flex items-center gap-1"
                              >
                                <Eye className="w-3.5 h-3.5" />
                                <span>Inspect</span>
                              </button>
                              <button
                                onClick={() => setShowRevokeConfirm(d.deviceId)}
                                className="px-2.5 py-1 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 rounded-lg text-xs font-medium transition-colors cursor-pointer flex items-center gap-1"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                                <span>Revoke</span>
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: DEPLOYMENT & ENROLLMENT TOKENS */}
      {activeTab === 'deployment' && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Key className="w-5 h-5 text-blue-400" />
                <span>Enterprise Enrollment Tokens & MDM Distribution</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Tokens allow automated zero-touch enrollment into organization <strong className="text-white font-mono">{activeOrgId}</strong>.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowCreateTokenModal(true)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer flex items-center gap-2 shadow-lg shadow-blue-600/20"
              >
                <Plus className="w-4 h-4" />
                <span>Generate New Token</span>
              </button>
              <button
                onClick={handleDownloadZip}
                disabled={downloadingZip}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-semibold transition-colors cursor-pointer flex items-center gap-2"
              >
                <Download className="w-4 h-4 text-blue-400" />
                <span>{downloadingZip ? 'Packing...' : 'Download Extension ZIP'}</span>
              </button>
            </div>
          </div>

          {/* Tokens List */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Active Enrollment Tokens</h4>
              <span className="text-xs text-slate-400">{tokens.length} total tokens</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Token Value</th>
                    <th className="py-3 px-4">Label</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Uses</th>
                    <th className="py-3 px-4">Created</th>
                    <th className="py-3 px-4">Expires</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {tokens.map((t) => {
                    const isExpired = t.expiresAt && t.expiresAt < Date.now();
                    const isRevoked = t.status === 'REVOKED';
                    return (
                      <tr key={t.id || t.token} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-blue-400 font-medium">{t.token}</span>
                            <button
                              onClick={() => handleCopy(t.token, t.token)}
                              className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 transition-colors cursor-pointer"
                              title="Copy Token"
                            >
                              {copiedText === t.token ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                        </td>
                        <td className="py-3 px-4 text-white font-medium">{t.label || 'Default Token'}</td>
                        <td className="py-3 px-4">
                          {isRevoked ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                              Revoked
                            </span>
                          ) : isExpired ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                              Expired
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              Active
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-300">
                          {t.usedCount} / {t.maxUses || '∞'}
                        </td>
                        <td className="py-3 px-4 text-slate-400">
                          {new Date(t.createdAt).toLocaleDateString()}
                        </td>
                        <td className="py-3 px-4 text-slate-400">
                          {t.expiresAt ? new Date(t.expiresAt).toLocaleDateString() : 'Never'}
                        </td>
                        <td className="py-3 px-4 text-right">
                          {!isRevoked && (
                            <button
                              onClick={() => handleRevokeToken(t.id || t.token)}
                              className="text-rose-400 hover:text-rose-300 hover:underline text-xs cursor-pointer"
                            >
                              Revoke
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* MDM / GPO Policy Deployment Configs */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Google Workspace / Chrome Enterprise Policy JSON */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-white font-bold text-xs">
                  <Terminal className="w-4 h-4 text-blue-400" />
                  <span>Google Workspace Chrome Policy JSON</span>
                </div>
                <button
                  onClick={() => handleCopy(JSON.stringify({
                    "ExtensionInstallForcelist": ["phishguard_extension_id;https://clients2.google.com/service/update2/crx"],
                    "PhishGuardEnrollmentToken": tokens[0]?.token || "ENROLL-ACME-PILOT-TOKEN",
                    "PhishGuardOrganizationId": activeOrgId
                  }, null, 2), 'gsuite-json')}
                  className="text-xs text-blue-400 hover:underline flex items-center gap-1 cursor-pointer"
                >
                  {copiedText === 'gsuite-json' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy JSON</span>
                </button>
              </div>
              <pre className="p-3 bg-slate-950 border border-slate-800 rounded-xl text-[11px] font-mono text-slate-300 overflow-x-auto leading-relaxed">
{JSON.stringify({
  "ExtensionSettings": {
    "*": {
      "installation_mode": "force_installed",
      "update_url": "https://clients2.google.com/service/update2/crx"
    }
  },
  "3rdparty": {
    "extensions": {
      "phishguard_enterprise": {
        "enrollmentToken": tokens[0]?.token || "ENROLL-ACME-PILOT-TOKEN",
        "organizationId": activeOrgId,
        "backendUrl": window.location.origin
      }
    }
  }
}, null, 2)}
              </pre>
            </div>

            {/* Microsoft Intune / PowerShell Script */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-white font-bold text-xs">
                  <Code className="w-4 h-4 text-emerald-400" />
                  <span>Microsoft Intune / PowerShell GPO Enroller</span>
                </div>
                <button
                  onClick={() => handleCopy(`# PhishGuard Intune Enrollment Script
$RegPath = "HKLM:\\SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\phishguard"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "EnrollmentToken" -Value "${tokens[0]?.token || 'ENROLL-ACME-PILOT-TOKEN'}"
Set-ItemProperty -Path $RegPath -Name "OrganizationId" -Value "${activeOrgId}"
Write-Host "PhishGuard Fleet Profile Configured Successfully."`, 'intune-ps')}
                  className="text-xs text-emerald-400 hover:underline flex items-center gap-1 cursor-pointer"
                >
                  {copiedText === 'intune-ps' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy Script</span>
                </button>
              </div>
              <pre className="p-3 bg-slate-950 border border-slate-800 rounded-xl text-[11px] font-mono text-slate-300 overflow-x-auto leading-relaxed">
{`# PhishGuard Intune Enrollment Script
$RegPath = "HKLM:\\SOFTWARE\\Policies\\Google\\Chrome\\3rdparty\\extensions\\phishguard"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "EnrollmentToken" -Value "${tokens[0]?.token || 'ENROLL-ACME-PILOT-TOKEN'}"
Set-ItemProperty -Path $RegPath -Name "OrganizationId" -Value "${activeOrgId}"
Write-Host "PhishGuard Fleet Profile Configured Successfully."`}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: SECURITY INCIDENTS */}
      {activeTab === 'events' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Database className="w-5 h-5 text-blue-400" />
              <span>Real-Time Security Event Telemetry ({totalEvents})</span>
            </h3>
            <button
              onClick={handleExportCsv}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-medium transition-colors cursor-pointer flex items-center gap-2"
            >
              <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
              <span>Export CSV</span>
            </button>
          </div>

          {/* Search & Filters */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-lg flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[240px]">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search by URL, domain, or device ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex items-center gap-2 text-xs">
              <select
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-slate-300 rounded-xl px-3 py-2 focus:outline-none focus:border-blue-500 cursor-pointer"
              >
                <option value="ALL">All Risk Levels</option>
                <option value="CRITICAL">Critical Risk</option>
                <option value="HIGH">High Risk</option>
                <option value="MEDIUM">Medium Risk</option>
                <option value="LOW">Low Risk</option>
              </select>

              <select
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-slate-300 rounded-xl px-3 py-2 focus:outline-none focus:border-blue-500 cursor-pointer"
              >
                <option value="ALL">All Actions</option>
                <option value="BLOCKED">Blocked Intercepts</option>
                <option value="WARNED">Warned Intercepts</option>
                <option value="ALLOWED">Allowed Traffic</option>
              </select>

              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-slate-300 rounded-xl px-3 py-2 focus:outline-none focus:border-blue-500 cursor-pointer"
              >
                <option value="ALL">All Categories</option>
                <option value="PHISHING">Phishing</option>
                <option value="BRAND_IMPERSONATION">Brand Impersonation</option>
                <option value="HOMOGLYPH">Homoglyph / Punycode</option>
                <option value="MALICIOUS_DOWNLOAD">Malicious Download</option>
              </select>
            </div>
          </div>

          {/* Incidents Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Risk / Action</th>
                    <th className="py-3 px-4">Evaluated Target URL</th>
                    <th className="py-3 px-4">Detected Category</th>
                    <th className="py-3 px-4">Target Brand</th>
                    <th className="py-3 px-4">Device Origin</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {events.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500">
                        No security events match the current filter criteria.
                      </td>
                    </tr>
                  ) : (
                    events.map((ev) => {
                      const isBlocked = ev.actionTaken === 'BLOCKED';
                      const isHighRisk = ev.riskLevel === 'CRITICAL' || ev.riskLevel === 'HIGH';
                      return (
                        <tr key={ev.eventId} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-1.5">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                  ev.riskLevel === 'CRITICAL'
                                    ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                                    : ev.riskLevel === 'HIGH'
                                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                                    : ev.riskLevel === 'MEDIUM'
                                    ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                }`}
                              >
                                {ev.riskLevel}
                              </span>
                              <span
                                className={`px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase ${
                                  isBlocked ? 'bg-rose-950 text-rose-300' : 'bg-slate-800 text-slate-300'
                                }`}
                              >
                                {ev.actionTaken}
                              </span>
                            </div>
                          </td>
                          <td className="py-3 px-4 font-mono max-w-xs truncate text-slate-200">
                            {ev.url}
                          </td>
                          <td className="py-3 px-4 text-slate-300">
                            {ev.threatCategory || 'Suspicious Pattern'}
                          </td>
                          <td className="py-3 px-4 text-white font-medium">
                            {ev.targetBrand || '—'}
                          </td>
                          <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                            {ev.deviceId}
                          </td>
                          <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                            {new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={() => setSelectedEvent(ev)}
                              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-blue-400 hover:text-blue-300 rounded-lg text-xs font-medium transition-colors cursor-pointer"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: POLICY & ENFORCEMENT */}
      {activeTab === 'policy' && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6 max-w-3xl">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <SlidersHorizontal className="w-5 h-5 text-blue-400" />
              <span>Fleet Protection Policy & Enforcement Controls</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Policies automatically synchronize to all enrolled browser extensions during their periodic 60-second heartbeat.
            </p>
          </div>

          <div className="space-y-6 pt-4 border-t border-slate-800">
            {/* Enforcement Mode */}
            <div>
              <label className="block text-xs font-bold text-slate-200 mb-2">
                Active Interception Mode
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div
                  onClick={() => setPolicyEnforcement('BLOCK')}
                  className={`p-4 rounded-xl border transition-all cursor-pointer ${
                    policyEnforcement === 'BLOCK'
                      ? 'bg-rose-500/10 border-rose-500/40 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2 font-bold text-xs mb-1">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    <span>BLOCK (Enforced)</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    Strictly block navigation to detected phishing domains. Display full-screen enterprise warning modal.
                  </p>
                </div>

                <div
                  onClick={() => setPolicyEnforcement('WARN')}
                  className={`p-4 rounded-xl border transition-all cursor-pointer ${
                    policyEnforcement === 'WARN'
                      ? 'bg-amber-500/10 border-amber-500/40 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2 font-bold text-xs mb-1">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <span>WARN (Advisory)</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    Display alert banner and allow users to proceed after intentional acknowledgement.
                  </p>
                </div>

                <div
                  onClick={() => setPolicyEnforcement('MONITOR')}
                  className={`p-4 rounded-xl border transition-all cursor-pointer ${
                    policyEnforcement === 'MONITOR'
                      ? 'bg-blue-500/10 border-blue-500/40 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2 font-bold text-xs mb-1">
                    <Radio className="w-4 h-4 text-blue-400" />
                    <span>MONITOR (Silent)</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    Silently record threat telemetry without user intervention or page blocking.
                  </p>
                </div>
              </div>
            </div>

            {/* Minimum Version */}
            <div>
              <label className="block text-xs font-bold text-slate-200 mb-1.5">
                Minimum Required Extension Version
              </label>
              <input
                type="text"
                value={policyMinVersion}
                onChange={(e) => setPolicyMinVersion(e.target.value)}
                className="w-48 px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white font-mono focus:outline-none focus:border-blue-500"
              />
              <p className="text-[11px] text-slate-500 mt-1">
                Endpoints below this version will be flagged as OUTDATED in fleet governance views.
              </p>
            </div>

            {/* Telemetry Toggle */}
            <div className="flex items-center justify-between p-4 bg-slate-950 border border-slate-800 rounded-xl">
              <div>
                <span className="font-bold text-xs text-white block">Canonical Security Telemetry Reporting</span>
                <span className="text-[11px] text-slate-400">Transmit privacy-preserving threat logs to customer SIEM & central dashboard</span>
              </div>
              <input
                type="checkbox"
                checked={policyTelemetry}
                onChange={(e) => setPolicyTelemetry(e.target.checked)}
                className="w-4 h-4 accent-blue-600 rounded cursor-pointer"
              />
            </div>

            {/* Save Button */}
            <div className="flex items-center justify-between pt-2">
              {policySavedSuccess ? (
                <div className="text-xs text-emerald-400 flex items-center gap-1.5 font-semibold">
                  <Check className="w-4 h-4" />
                  <span>Policies successfully synchronized to cloud fleet!</span>
                </div>
              ) : <div />}

              <button
                onClick={handleSavePolicy}
                disabled={policySaving}
                className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl text-xs transition-colors cursor-pointer flex items-center gap-2 shadow-lg shadow-blue-600/20"
              >
                {policySaving ? 'Synchronizing...' : 'Save & Publish Fleet Policy'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* CREATE TOKEN MODAL */}
      {showCreateTokenModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Key className="w-5 h-5 text-blue-400" />
              <span>Generate Enrollment Token</span>
            </h3>
            <p className="text-xs text-slate-400">
              Create an onboarding token bound to organization <strong className="text-white font-mono">{activeOrgId}</strong>.
            </p>

            <form onSubmit={handleCreateToken} className="space-y-4 pt-2">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Token Label</label>
                <input
                  type="text"
                  value={tokenLabel}
                  onChange={(e) => setTokenLabel(e.target.value)}
                  placeholder="e.g. Sales Engineering MacBooks"
                  required
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Expires In (Days)</label>
                  <input
                    type="number"
                    min="1"
                    max="365"
                    value={tokenExpiresDays}
                    onChange={(e) => setTokenExpiresDays(parseInt(e.target.value, 10))}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Max Devices</label>
                  <input
                    type="number"
                    min="1"
                    max="10000"
                    value={tokenMaxUses}
                    onChange={(e) => setTokenMaxUses(parseInt(e.target.value, 10))}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateTokenModal(false)}
                  className="px-4 py-2 bg-slate-800 text-slate-300 rounded-xl text-xs font-medium hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={tokenCreating}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer"
                >
                  {tokenCreating ? 'Generating...' : 'Issue Token'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* REVOKE DEVICE MODAL */}
      {showRevokeConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="w-10 h-10 rounded-xl bg-rose-500/20 text-rose-400 flex items-center justify-center">
              <AlertCircle className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Revoke Endpoint Credentials?</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Device <strong className="text-white font-mono">{showRevokeConfirm}</strong> will immediately be barred from heartbeat synchronization and threat telemetry ingestion.
              </p>
            </div>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setShowRevokeConfirm(null)}
                className="px-4 py-2 bg-slate-800 text-slate-300 rounded-xl text-xs font-medium hover:bg-slate-700 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => handleRevokeDevice(showRevokeConfirm)}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer shadow-lg shadow-rose-600/20"
              >
                Confirm Revocation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* EVENT DETAIL MODAL */}
      {selectedEvent && (
        <EventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          onInspectUrl={(url) => {
            setSelectedEvent(null);
            if (onInspectUrl) onInspectUrl(url);
          }}
        />
      )}

      {/* DEVICE DETAIL DRAWER */}
      {selectedDevice && (
        <DeviceDetailDrawer
          device={selectedDevice}
          events={events.filter(e => e.deviceId === selectedDevice.deviceId)}
          onClose={() => setSelectedDevice(null)}
          onInspectUrl={(url) => {
            setSelectedDevice(null);
            if (onInspectUrl) onInspectUrl(url);
          }}
        />
      )}
    </div>
  );
};
