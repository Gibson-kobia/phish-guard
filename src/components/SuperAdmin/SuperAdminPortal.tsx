import React, { useState, useEffect } from 'react';
import {
  Shield,
  Building2,
  Users,
  Laptop,
  Key,
  Database,
  Plus,
  RefreshCw,
  Search,
  Filter,
  Check,
  X,
  AlertCircle,
  AlertTriangle,
  Play,
  Terminal,
  Activity,
  Trash2,
  Lock,
  Pause,
  ArrowRight,
  Eye,
  Server,
  Cpu,
  FileSpreadsheet,
  Layers,
  Settings
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { Organization, EnrolledDevice, AuditLogEntry } from '../../core/types';
import { AdminUser } from '../../server/storage/types';

export type SuperAdminModule =
  | 'overview'
  | 'organizations'
  | 'fleet'
  | 'events'
  | 'users'
  | 'audit'
  | 'diagnostics';

interface SuperAdminPortalProps {
  onSwitchToCustomerView?: (orgId: string) => void;
}

export const SuperAdminPortal: React.FC<SuperAdminPortalProps> = ({ onSwitchToCustomerView }) => {
  const { user, authFetch, logout } = useAuth();
  const [activeModule, setActiveModule] = useState<SuperAdminModule>('overview');

  // Data states
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [devices, setDevices] = useState<EnrolledDevice[]>([]);
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [healthData, setHealthData] = useState<any>(null);

  // Search/Filters
  const [orgSearch, setOrgSearch] = useState('');
  const [deviceSearch, setDeviceSearch] = useState('');
  const [selectedOrgFilter, setSelectedOrgFilter] = useState('ALL');

  // Modals
  const [showCreateOrgModal, setShowCreateOrgModal] = useState(false);
  const [showCreateUserModal, setShowCreateUserModal] = useState(false);

  // Create Org Form
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgId, setNewOrgId] = useState('');
  const [newOrgDomain, setNewOrgDomain] = useState('');
  const [newOrgEmail, setNewOrgEmail] = useState('');
  const [newOrgPlan, setNewOrgPlan] = useState('ENTERPRISE_PILOT');
  const [newOrgMode, setNewOrgMode] = useState<'BLOCK' | 'WARN' | 'MONITOR'>('BLOCK');
  const [creatingOrg, setCreatingOrg] = useState(false);

  // Create User Form
  const [newUserName, setNewUserName] = useState('');
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserRole, setNewUserRole] = useState<'SUPER_ADMIN' | 'ORG_ADMIN' | 'READ_ONLY' | 'INDIVIDUAL'>('ORG_ADMIN');
  const [newUserOrgId, setNewUserOrgId] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [creatingUser, setCreatingUser] = useState(false);

  const fetchAdminData = async () => {
    try {
      setRefreshing(true);
      const [hRes, orgRes, devRes, userRes, audRes, evRes] = await Promise.all([
        authFetch('/api/health'),
        authFetch('/api/admin/organizations'),
        authFetch('/api/admin/devices'),
        authFetch('/api/admin/users'),
        authFetch('/api/admin/audit'),
        authFetch('/api/admin/events')
      ]);

      if (hRes.ok) setHealthData(await hRes.json());

      if (orgRes.ok) {
        const orgData = await orgRes.json();
        const rawOrgs: Organization[] = orgData.organizations || [];
        const uniqueOrgs = Array.from(new Map(rawOrgs.map((o) => [o.organizationId, o])).values());
        setOrganizations(uniqueOrgs);
        if (uniqueOrgs.length > 0 && !newUserOrgId) {
          setNewUserOrgId(uniqueOrgs[0].organizationId);
        }
      }

      if (devRes.ok) {
        const devData = await devRes.json();
        setDevices(devData.devices || []);
      }

      if (userRes.ok) {
        const userData = await userRes.json();
        setAdminUsers(userData.users || []);
      }

      if (audRes.ok) {
        const audData = await audRes.json();
        setAuditLogs(audData.logs || []);
      }

      if (evRes.ok) {
        const evData = await evRes.json();
        setEvents(evData.events || []);
      }
    } catch (err) {
      console.error('Failed to load super admin data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchAdminData();
  }, []);

  const handleCreateOrganization = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setCreatingOrg(true);
      const generatedId =
        newOrgId.trim() ||
        `ORG-${newOrgName.trim().toUpperCase().replace(/[^A-Z0-9]/g, '-').slice(0, 15)}`;
      const res = await authFetch('/api/admin/organizations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          organizationId: generatedId,
          name: newOrgName,
          domain: newOrgDomain || `${newOrgName.toLowerCase().replace(/[^a-z0-9]/g, '')}.com`,
          contactEmail: newOrgEmail || `admin@${newOrgDomain || 'company.com'}`,
          plan: newOrgPlan,
          enforcementMode: newOrgMode,
          status: 'ACTIVE'
        })
      });
      if (res.ok) {
        setShowCreateOrgModal(false);
        setNewOrgName('');
        setNewOrgId('');
        setNewOrgDomain('');
        setNewOrgEmail('');
        await fetchAdminData();
      }
    } catch (err) {
      console.error('Failed to provision organization:', err);
    } finally {
      setCreatingOrg(false);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setCreatingUser(true);
      const res = await authFetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newUserName,
          email: newUserEmail,
          role: newUserRole,
          organizationId: newUserRole === 'SUPER_ADMIN' || newUserRole === 'INDIVIDUAL' ? undefined : newUserOrgId,
          password: newUserPassword || 'SecOpsSecurePass2026!'
        })
      });
      if (res.ok) {
        setShowCreateUserModal(false);
        setNewUserName('');
        setNewUserEmail('');
        setNewUserPassword('');
        await fetchAdminData();
      }
    } catch (err) {
      console.error('Failed to create user:', err);
    } finally {
      setCreatingUser(false);
    }
  };

  const handleToggleOrgStatus = async (orgId: string, currentStatus: string) => {
    try {
      const nextStatus = currentStatus === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE';
      await authFetch(`/api/admin/organizations/${orgId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: nextStatus })
      });
      await fetchAdminData();
    } catch (err) {
      console.error('Failed to toggle org status:', err);
    }
  };

  const handleRevokeDevice = async (deviceId: string) => {
    if (!confirm('Are you sure you want to revoke this endpoint device?')) return;
    try {
      await authFetch(`/api/admin/devices/${deviceId}/revoke`, { method: 'POST' });
      await fetchAdminData();
    } catch (err) {
      console.error('Failed to revoke device:', err);
    }
  };

  const filteredOrgs = organizations.filter(
    (o) =>
      o.name.toLowerCase().includes(orgSearch.toLowerCase()) ||
      o.organizationId.toLowerCase().includes(orgSearch.toLowerCase()) ||
      (o.domain && o.domain.toLowerCase().includes(orgSearch.toLowerCase()))
  );

  const filteredDevices = devices.filter((d) => {
    const matchSearch =
      d.deviceName.toLowerCase().includes(deviceSearch.toLowerCase()) ||
      d.id.toLowerCase().includes(deviceSearch.toLowerCase()) ||
      d.organizationId.toLowerCase().includes(deviceSearch.toLowerCase());
    const matchOrg = selectedOrgFilter === 'ALL' || d.organizationId === selectedOrgFilter;
    return matchSearch && matchOrg;
  });

  return (
    <div className="flex min-h-[85vh] bg-slate-950 rounded-2xl border border-slate-800 overflow-hidden shadow-2xl">
      {/* 1. LEFT SIDEBAR (No horizontal scrollbar, clean vertical layout) */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between flex-shrink-0">
        <div className="p-4 space-y-6">
          {/* Super Admin Title */}
          <div className="flex items-center gap-3 px-2">
            <div className="w-8 h-8 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-xs font-bold text-white tracking-tight">SecOps Control Plane</h2>
              <span className="text-[10px] text-indigo-400 font-mono">SUPER_ADMIN</span>
            </div>
          </div>

          {/* Nav Items */}
          <nav className="space-y-1 text-xs">
            <button
              onClick={() => setActiveModule('overview')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl font-semibold transition-all cursor-pointer ${
                activeModule === 'overview'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span>Platform Overview</span>
            </button>

            <button
              onClick={() => setActiveModule('organizations')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl font-semibold transition-all cursor-pointer ${
                activeModule === 'organizations'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Building2 className="w-4 h-4" />
              <span>Fleet Organizations</span>
              <span className="ml-auto text-[10px] bg-slate-800 px-1.5 py-0.2 rounded text-slate-300">
                {organizations.length}
              </span>
            </button>

            <button
              onClick={() => setActiveModule('fleet')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl font-semibold transition-all cursor-pointer ${
                activeModule === 'fleet'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Laptop className="w-4 h-4" />
              <span>Enrolled Endpoints</span>
              <span className="ml-auto text-[10px] bg-slate-800 px-1.5 py-0.2 rounded text-slate-300">
                {devices.length}
              </span>
            </button>

            <button
              onClick={() => setActiveModule('events')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl font-semibold transition-all cursor-pointer ${
                activeModule === 'events'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Shield className="w-4 h-4" />
              <span>Threat Feed</span>
              <span className="ml-auto text-[10px] bg-slate-800 px-1.5 py-0.2 rounded text-slate-300">
                {events.length}
              </span>
            </button>

            <button
              onClick={() => setActiveModule('users')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl font-semibold transition-all cursor-pointer ${
                activeModule === 'users'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Users className="w-4 h-4" />
              <span>Admin Users & RBAC</span>
              <span className="ml-auto text-[10px] bg-slate-800 px-1.5 py-0.2 rounded text-slate-300">
                {adminUsers.length}
              </span>
            </button>

            <button
              onClick={() => setActiveModule('audit')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl font-semibold transition-all cursor-pointer ${
                activeModule === 'audit'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Terminal className="w-4 h-4" />
              <span>Global Audit Logs</span>
            </button>

            <button
              onClick={() => setActiveModule('diagnostics')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl font-semibold transition-all cursor-pointer ${
                activeModule === 'diagnostics'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Database className="w-4 h-4" />
              <span>Platform Diagnostics</span>
            </button>
          </nav>
        </div>

        {/* Operator Profile Bottom */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 text-xs">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-semibold text-white">{user?.name || 'Operator'}</div>
              <div className="text-[10px] text-slate-500 font-mono truncate">{user?.email}</div>
            </div>
            <button
              onClick={logout}
              className="text-rose-400 hover:text-rose-300 text-xs hover:underline cursor-pointer"
            >
              Sign Out
            </button>
          </div>
        </div>
      </aside>

      {/* 2. MAIN CONTENT AREA */}
      <main className="flex-1 flex flex-col min-w-0 bg-slate-950 overflow-y-auto">
        {/* Top Header */}
        <div className="h-14 border-b border-slate-800 px-6 flex items-center justify-between bg-slate-900/40">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-500">Fleet Management</span>
            <span className="text-slate-600">/</span>
            <span className="text-white font-semibold capitalize">{activeModule}</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchAdminData}
              disabled={refreshing}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors cursor-pointer flex items-center gap-1.5 text-xs"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Tab Content */}
        <div className="p-6 space-y-6">
          {/* MODULE 1: PLATFORM OVERVIEW */}
          {activeModule === 'overview' && (
            <div className="space-y-6">
              {/* Stat Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>Fleet Organizations</span>
                    <Building2 className="w-4 h-4 text-blue-400" />
                  </div>
                  <div className="text-2xl font-extrabold text-white">{organizations.length}</div>
                  <p className="text-[11px] text-slate-500">Active tenant domains</p>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>Protected Endpoints</span>
                    <Laptop className="w-4 h-4 text-indigo-400" />
                  </div>
                  <div className="text-2xl font-extrabold text-white">{devices.length}</div>
                  <p className="text-[11px] text-slate-500">Enrolled Chrome browser instances</p>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>Threats Intercepted</span>
                    <Shield className="w-4 h-4 text-rose-400" />
                  </div>
                  <div className="text-2xl font-extrabold text-white">{events.length}</div>
                  <p className="text-[11px] text-slate-500">Phishing & malicious download traps</p>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>System Status</span>
                    <Server className="w-4 h-4 text-emerald-400" />
                  </div>
                  <div className="text-2xl font-extrabold text-white flex items-center gap-2">
                    <span>Operational</span>
                    <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  </div>
                  <p className="text-[11px] text-slate-500">Runtime: {healthData?.runtime || 'Cloud Service Active'}</p>
                </div>
              </div>

              {/* Quick Fleets List */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white">Active Tenant Fleets</h3>
                    <p className="text-xs text-slate-400">Manage customer organizations and policy states</p>
                  </div>
                  <button
                    onClick={() => setShowCreateOrgModal(true)}
                    className="py-1.5 px-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 cursor-pointer shadow-sm"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>New Organization</span>
                  </button>
                </div>

                <div className="divide-y divide-slate-800/60">
                  {organizations.slice(0, 5).map((org) => (
                    <div key={org.organizationId} className="py-3 flex items-center justify-between gap-4 text-xs">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                          <Building2 className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="font-semibold text-white">{org.name}</div>
                          <div className="text-[11px] text-slate-400 font-mono">{org.organizationId}</div>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                          {org.enforcementMode || 'BLOCK'}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            org.status === 'ACTIVE'
                              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          }`}
                        >
                          {org.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* MODULE 2: ORGANIZATIONS */}
          {activeModule === 'organizations' && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="relative flex-1 max-w-sm">
                  <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={orgSearch}
                    onChange={(e) => setOrgSearch(e.target.value)}
                    placeholder="Search organizations..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <button
                  onClick={() => setShowCreateOrgModal(true)}
                  className="py-2 px-4 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold flex items-center gap-2 cursor-pointer shadow-md shadow-indigo-600/20"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Create Organization</span>
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-3 px-4">Organization</th>
                      <th className="py-3 px-4">Domain</th>
                      <th className="py-3 px-4">Enforcement</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {filteredOrgs.map((org) => (
                      <tr key={org.organizationId} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-4">
                          <div className="font-semibold text-white">{org.name}</div>
                          <div className="text-[11px] text-slate-500 font-mono">{org.organizationId}</div>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400">{org.domain || 'N/A'}</td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                            {org.enforcementMode || 'BLOCK'}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              org.status === 'ACTIVE'
                                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                                : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            }`}
                          >
                            {org.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right space-x-2">
                          <button
                            onClick={() => handleToggleOrgStatus(org.organizationId, org.status)}
                            className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] border border-slate-700 cursor-pointer"
                          >
                            {org.status === 'ACTIVE' ? 'Suspend' : 'Activate'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* MODULE 3: FLEET DEVICES */}
          {activeModule === 'fleet' && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="relative flex-1 max-w-sm">
                  <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={deviceSearch}
                    onChange={(e) => setDeviceSearch(e.target.value)}
                    placeholder="Search devices by name, ID or org..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-3 px-4">Device</th>
                      <th className="py-3 px-4">Organization</th>
                      <th className="py-3 px-4">Browser / OS</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {filteredDevices.map((dev) => (
                      <tr key={dev.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-4">
                          <div className="font-semibold text-white">{dev.deviceName}</div>
                          <div className="text-[11px] text-slate-500 font-mono">{dev.id}</div>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400">{dev.organizationId}</td>
                        <td className="py-3 px-4 text-slate-400">
                          {dev.browser} • v{dev.extensionVersion}
                        </td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                            {dev.status || 'ACTIVE'}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => handleRevokeDevice(dev.id)}
                            className="px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 text-[11px] border border-rose-500/20 cursor-pointer"
                          >
                            Revoke
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* MODULE 4: THREAT EVENTS STREAM */}
          {activeModule === 'events' && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div>
                <h3 className="text-sm font-bold text-white">Cross-Fleet Threat Stream</h3>
                <p className="text-xs text-slate-400">
                  Real-time threat interception events ingested from fleet endpoints
                </p>
              </div>

              <div className="divide-y divide-slate-800/60">
                {events.map((ev) => (
                  <div key={ev.eventId || ev.id} className="py-3.5 flex items-center justify-between gap-4 text-xs">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
                        <AlertTriangle className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="font-semibold text-white font-mono">{ev.domain || ev.url}</div>
                        <div className="text-[11px] text-slate-400">
                          Org: <span className="font-mono text-slate-300">{ev.organizationId}</span> • Vector:{' '}
                          {ev.category || 'Phishing Trap'}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="text-[11px] text-slate-500">
                        {new Date(ev.timestamp || Date.now()).toLocaleTimeString()}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                        INTERCEPTED
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* MODULE 5: ADMIN USERS & RBAC */}
          {activeModule === 'users' && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white">Platform Users & RBAC</h3>
                  <p className="text-xs text-slate-400">Manage Super Admins, Org Admins, and subscribers</p>
                </div>
                <button
                  onClick={() => setShowCreateUserModal(true)}
                  className="py-2 px-4 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold flex items-center gap-2 cursor-pointer shadow-md"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Create User</span>
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-3 px-4">User</th>
                      <th className="py-3 px-4">Role</th>
                      <th className="py-3 px-4">Organization</th>
                      <th className="py-3 px-4">Last Login</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {adminUsers.map((u) => (
                      <tr key={u.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-4">
                          <div className="font-semibold text-white">{u.name}</div>
                          <div className="text-[11px] text-slate-500">{u.email}</div>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              u.role === 'SUPER_ADMIN'
                                ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                                : u.role === 'INDIVIDUAL'
                                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                                : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                            }`}
                          >
                            {u.role}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400">{u.organizationId || 'Global Platform'}</td>
                        <td className="py-3 px-4 text-slate-500">
                          {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleDateString() : 'Never'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* MODULE 6: GLOBAL AUDIT LOGS */}
          {activeModule === 'audit' && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div>
                <h3 className="text-sm font-bold text-white">Immutable Platform Audit Logs</h3>
                <p className="text-xs text-slate-400">Cryptographically tracked administrative operations</p>
              </div>

              <div className="divide-y divide-slate-800/60">
                {auditLogs.map((log) => (
                  <div key={log.id} className="py-3 flex items-center justify-between gap-4 text-xs">
                    <div>
                      <div className="font-semibold text-white">{log.action}</div>
                      <div className="text-[11px] text-slate-400">
                        Actor: <strong className="text-slate-300">{log.actor}</strong> • Org:{' '}
                        <span className="font-mono text-slate-400">{log.organizationId || 'GLOBAL'}</span>
                      </div>
                    </div>
                    <span className="text-[11px] text-slate-500 font-mono">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* MODULE 7: PLATFORM DIAGNOSTICS */}
          {activeModule === 'diagnostics' && (
            <div className="space-y-6">
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div className="flex items-center gap-3">
                  <Database className="w-5 h-5 text-emerald-400" />
                  <div>
                    <h3 className="text-sm font-bold text-white">Infrastructure & Platform Diagnostics</h3>
                    <p className="text-xs text-slate-400">Production multi-tenant database & service connectivity</p>
                  </div>
                </div>

                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs space-y-2 text-slate-300">
                  <div>Authoritative Database: <strong>{healthData?.database?.type || 'Supabase PostgreSQL (Cloud)'}</strong></div>
                  <div>Database State: <span className="text-emerald-400 font-bold">{healthData?.database?.status || 'ONLINE'}</span></div>
                  <div>Runtime Environment: <span className="text-indigo-400">{healthData?.runtime || 'Production Serverless'}</span></div>
                  <div>Enrolled Fleets: {organizations.length}</div>
                  <div>Active Endpoints: {devices.length}</div>
                  <div>Intercepted Security Events: {events.length}</div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* CREATE ORG MODAL */}
      {showCreateOrgModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white">Provision Customer Fleet Organization</h3>
              <button onClick={() => setShowCreateOrgModal(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateOrganization} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Organization Name</label>
                <input
                  type="text"
                  required
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  placeholder="e.g. Apex Global Corp"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Domain</label>
                <input
                  type="text"
                  value={newOrgDomain}
                  onChange={(e) => setNewOrgDomain(e.target.value)}
                  placeholder="apex-global.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={creatingOrg}
                  className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-semibold cursor-pointer shadow-md"
                >
                  {creatingOrg ? 'Provisioning...' : 'Provision Organization'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CREATE USER MODAL */}
      {showCreateUserModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white">Create Platform / Customer User</h3>
              <button onClick={() => setShowCreateUserModal(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateUser} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={newUserName}
                  onChange={(e) => setNewUserName(e.target.value)}
                  placeholder="e.g. Dana Scully"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Email Address</label>
                <input
                  type="email"
                  required
                  value={newUserEmail}
                  onChange={(e) => setNewUserEmail(e.target.value)}
                  placeholder="user@organization.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Role</label>
                <select
                  value={newUserRole}
                  onChange={(e: any) => setNewUserRole(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-indigo-500"
                >
                  <option value="ORG_ADMIN">Customer Org Admin</option>
                  <option value="READ_ONLY">Read Only Analyst</option>
                  <option value="INDIVIDUAL">Individual Customer</option>
                  <option value="SUPER_ADMIN">Platform Super Admin</option>
                </select>
              </div>

              {newUserRole !== 'SUPER_ADMIN' && newUserRole !== 'INDIVIDUAL' && (
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Assign Organization</label>
                  <select
                    value={newUserOrgId}
                    onChange={(e) => setNewUserOrgId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-indigo-500"
                  >
                    {organizations.map((o) => (
                      <option key={o.organizationId} value={o.organizationId}>
                        {o.name} ({o.organizationId})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Initial Password</label>
                <input
                  type="password"
                  required
                  minLength={8}
                  value={newUserPassword}
                  onChange={(e) => setNewUserPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={creatingUser}
                  className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-semibold cursor-pointer shadow-md"
                >
                  {creatingUser ? 'Creating...' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
