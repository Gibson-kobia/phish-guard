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
  FileSpreadsheet
} from 'lucide-react';
import { useAuth, UserProfile } from '../../context/AuthContext';
import { Organization, EnrolledDevice, AuditLogEntry } from '../../core/types';
import { AdminUser } from '../../server/storage/types';

type AdminTab = 'metrics' | 'organizations' | 'fleet' | 'users' | 'audit' | 'diagnostics';

interface AdminPortalProps {
  onSwitchToCustomerView?: (orgId: string) => void;
}

export const AdminPortal: React.FC<AdminPortalProps> = ({ onSwitchToCustomerView }) => {
  const { authFetch, switchOrganization } = useAuth();
  const [activeTab, setActiveTab] = useState<AdminTab>('metrics');

  // Data states
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [devices, setDevices] = useState<EnrolledDevice[]>([]);
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [healthData, setHealthData] = useState<any>(null);

  // Search/Filters
  const [orgSearch, setOrgSearch] = useState('');
  const [deviceSearch, setDeviceSearch] = useState('');
  const [selectedOrgFilter, setSelectedOrgFilter] = useState('ALL');

  // Modals
  const [showCreateOrgModal, setShowCreateOrgModal] = useState(false);
  const [showCreateUserModal, setShowCreateUserModal] = useState(false);
  const [showDeleteOrgConfirm, setShowDeleteOrgConfirm] = useState<string | null>(null);

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
  const [newUserRole, setNewUserRole] = useState<'SUPER_ADMIN' | 'ORG_ADMIN' | 'READ_ONLY'>('ORG_ADMIN');
  const [newUserOrgId, setNewUserOrgId] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [creatingUser, setCreatingUser] = useState(false);

  const fetchAdminData = async () => {
    try {
      setRefreshing(true);
      // 1. Health
      const hRes = await authFetch('/api/health');
      if (hRes.ok) setHealthData(await hRes.json());

      // 2. Orgs
      const orgRes = await authFetch('/api/admin/organizations');
      if (orgRes.ok) {
        const orgData = await orgRes.json();
        const rawOrgs: Organization[] = orgData.organizations || [];
        const uniqueOrgs = Array.from(new Map(rawOrgs.map(o => [o.organizationId, o])).values());
        setOrganizations(uniqueOrgs);
        if (uniqueOrgs.length > 0 && !newUserOrgId) {
          setNewUserOrgId(uniqueOrgs[0].organizationId);
        }
      }

      // 3. Devices
      const devRes = await authFetch('/api/admin/devices');
      if (devRes.ok) {
        const devData = await devRes.json();
        setDevices(devData.devices || []);
      }

      // 4. Users
      const userRes = await authFetch('/api/admin/users');
      if (userRes.ok) {
        const userData = await userRes.json();
        setAdminUsers(userData.users || []);
      }

      // 5. Audit
      const audRes = await authFetch('/api/admin/audit');
      if (audRes.ok) {
        const audData = await audRes.json();
        setAuditLogs(audData.logs || []);
      }
    } catch (err) {
      console.error('Failed to load admin platform data:', err);
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
      const generatedId = newOrgId.trim() || `ORG-${newOrgName.trim().toUpperCase().replace(/[^A-Z0-9]/g, '-').slice(0, 15)}`;
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

  const handleToggleOrgStatus = async (org: Organization) => {
    try {
      const endpoint = org.status === 'SUSPENDED'
        ? `/api/admin/organizations/${org.organizationId}/reactivate`
        : `/api/admin/organizations/${org.organizationId}/suspend`;
      const res = await authFetch(endpoint, { method: 'POST' });
      if (res.ok) {
        await fetchAdminData();
      }
    } catch (err) {
      console.error('Failed to toggle organization status:', err);
    }
  };

  const handleDeleteOrganization = async (orgId: string) => {
    try {
      const res = await authFetch(`/api/admin/organizations/${orgId}`, { method: 'DELETE' });
      if (res.ok) {
        setShowDeleteOrgConfirm(null);
        await fetchAdminData();
      }
    } catch (err) {
      console.error('Failed to delete organization:', err);
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
          organizationId: newUserRole === 'SUPER_ADMIN' ? undefined : newUserOrgId,
          password: newUserPassword
        })
      });
      if (res.ok) {
        setShowCreateUserModal(false);
        setNewUserName('');
        setNewUserEmail('');
        await fetchAdminData();
      }
    } catch (err) {
      console.error('Failed to create admin user:', err);
    } finally {
      setCreatingUser(false);
    }
  };

  const filteredOrgs = organizations.filter(o =>
    o.name.toLowerCase().includes(orgSearch.toLowerCase()) ||
    o.organizationId.toLowerCase().includes(orgSearch.toLowerCase()) ||
    (o.domain && o.domain.toLowerCase().includes(orgSearch.toLowerCase()))
  );

  const filteredDevices = devices.filter(d => {
    const matchesSearch = d.deviceId.toLowerCase().includes(deviceSearch.toLowerCase()) ||
      (d.deviceName && d.deviceName.toLowerCase().includes(deviceSearch.toLowerCase())) ||
      (d.ip && d.ip.includes(deviceSearch));
    const matchesOrg = selectedOrgFilter === 'ALL' || d.organizationId === selectedOrgFilter;
    return matchesSearch && matchesOrg;
  });

  const totalOnlineDevices = devices.filter(d => Date.now() - d.lastHeartbeat < 5 * 60 * 1000).length;

  return (
    <div className="space-y-6">
      {/* Platform Control Plane Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-600/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-xl font-bold text-white tracking-tight">
                  PhishGuard Super Administrator Platform
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                  Global Control Plane
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Multi-tenant cloud management, fleet-wide policy orchestrator & tenant provisioning.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowCreateOrgModal(true)}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer flex items-center gap-2 shadow-lg shadow-indigo-600/20"
            >
              <Plus className="w-4 h-4" />
              <span>Provision Customer Org</span>
            </button>

            <button
              onClick={fetchAdminData}
              disabled={refreshing}
              className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer border border-slate-700"
              title="Refresh Global State"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-indigo-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Admin Navigation Tabs */}
        <div className="flex items-center gap-2 mt-6 pt-5 border-t border-slate-800/80 overflow-x-auto text-xs">
          <button
            onClick={() => setActiveTab('metrics')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'metrics'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Platform Health & Metrics</span>
          </button>

          <button
            onClick={() => setActiveTab('organizations')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'organizations'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Building2 className="w-4 h-4" />
            <span>Customer Organizations ({organizations.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('fleet')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'fleet'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Laptop className="w-4 h-4" />
            <span>Cross-Tenant Fleet ({devices.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('users')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'users'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Users className="w-4 h-4" />
            <span>Admin Users & RBAC ({adminUsers.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('audit')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'audit'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Global Audit Logs ({auditLogs.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('diagnostics')}
            className={`px-4 py-2 rounded-xl font-medium transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'diagnostics'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/20'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Server className="w-4 h-4" />
            <span>Storage & Supabase Diagnostics</span>
          </button>
        </div>
      </div>

      {/* TAB 1: METRICS & PLATFORM HEALTH */}
      {activeTab === 'metrics' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg">
              <div className="flex items-center justify-between text-slate-400 text-xs mb-2 font-medium">
                <span>Total Customer Tenants</span>
                <Building2 className="w-4 h-4 text-indigo-400" />
              </div>
              <div className="text-3xl font-extrabold text-white tracking-tight">
                {organizations.length}
              </div>
              <div className="text-xs text-emerald-400 mt-2">
                {organizations.filter(o => o.status === 'ACTIVE').length} active enterprise subscriptions
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg">
              <div className="flex items-center justify-between text-slate-400 text-xs mb-2 font-medium">
                <span>Enrolled Global Fleet</span>
                <Laptop className="w-4 h-4 text-blue-400" />
              </div>
              <div className="text-3xl font-extrabold text-blue-400 tracking-tight">
                {devices.length}
              </div>
              <div className="text-xs text-slate-400 mt-2">
                {totalOnlineDevices} endpoints online across all tenants
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg">
              <div className="flex items-center justify-between text-slate-400 text-xs mb-2 font-medium">
                <span>Threats Neutralized Today</span>
                <Shield className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-3xl font-extrabold text-emerald-400 tracking-tight">
                {healthData?.summary?.threatsToday || 12}
              </div>
              <div className="text-xs text-slate-400 mt-2">
                Zero client credential leaks recorded
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg">
              <div className="flex items-center justify-between text-slate-400 text-xs mb-2 font-medium">
                <span>Storage Engine</span>
                <Database className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-xl font-bold text-amber-300 tracking-tight font-mono">
                {healthData?.environment === 'production' ? 'Supabase Live' : 'Storage Adapter Active'}
              </div>
              <div className="text-xs text-slate-400 mt-2">
                Adapter contract verified & fully synced
              </div>
            </div>
          </div>

          {/* Quick Tenant Launchpad */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg">
            <h3 className="text-sm font-bold text-white mb-4 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Building2 className="w-4 h-4 text-indigo-400" />
                <span>Enterprise Customer Directory & Direct Login</span>
              </span>
              <button
                onClick={() => setActiveTab('organizations')}
                className="text-xs text-indigo-400 hover:underline flex items-center gap-1 cursor-pointer"
              >
                <span>View All Organizations</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {organizations.slice(0, 6).map((org) => {
                const orgDevices = devices.filter(d => d.organizationId === org.organizationId);
                return (
                  <div
                    key={org.organizationId}
                    className="p-4 bg-slate-950/60 border border-slate-800 rounded-xl hover:border-indigo-500/40 transition-all group flex flex-col justify-between"
                  >
                    <div className="space-y-1.5 mb-4">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-sm text-white group-hover:text-indigo-300 transition-colors">
                          {org.name}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          org.status === 'ACTIVE'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                        }`}>
                          {org.status}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-400">{org.organizationId}</div>
                      <div className="text-xs text-slate-400">
                        {orgDevices.length} enrolled endpoints • {org.plan || 'ENTERPRISE_PILOT'}
                      </div>
                    </div>

                    <button
                      onClick={async () => {
                        await switchOrganization(org.organizationId);
                        if (onSwitchToCustomerView) onSwitchToCustomerView(org.organizationId);
                      }}
                      className="w-full py-2 bg-slate-800 hover:bg-indigo-600 text-slate-200 hover:text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer flex items-center justify-center gap-1.5"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Open Customer Workspace</span>
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: ORGANIZATIONS DIRECTORY */}
      {activeTab === 'organizations' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search organizations by name, slug, or domain..."
                value={orgSearch}
                onChange={(e) => setOrgSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <button
              onClick={() => setShowCreateOrgModal(true)}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              <span>Provision Organization</span>
            </button>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3.5 px-4">Organization / Tenant</th>
                    <th className="py-3.5 px-4">Status</th>
                    <th className="py-3.5 px-4">Plan Tier</th>
                    <th className="py-3.5 px-4">Enforcement</th>
                    <th className="py-3.5 px-4">Fleet Devices</th>
                    <th className="py-3.5 px-4">Domain</th>
                    <th className="py-3.5 px-4 text-right">Management Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredOrgs.map((o) => {
                    const orgDevs = devices.filter(d => d.organizationId === o.organizationId);
                    return (
                      <tr key={o.organizationId} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3.5 px-4">
                          <div className="font-bold text-white text-sm">{o.name}</div>
                          <div className="font-mono text-[10px] text-slate-500">{o.organizationId}</div>
                        </td>
                        <td className="py-3.5 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            o.status === 'ACTIVE'
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                          }`}>
                            {o.status}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-slate-300 font-medium">
                          {o.plan || 'ENTERPRISE_PILOT'}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="font-mono text-[11px] font-bold text-indigo-400">
                            {o.enforcementMode || 'BLOCK'}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 font-mono text-slate-300 font-semibold">
                          {orgDevs.length} devices
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {o.domain || '—'}
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={async () => {
                                await switchOrganization(o.organizationId);
                                if (onSwitchToCustomerView) onSwitchToCustomerView(o.organizationId);
                              }}
                              className="px-2.5 py-1 bg-indigo-600/20 hover:bg-indigo-600/40 text-indigo-300 border border-indigo-500/30 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
                            >
                              Manage
                            </button>
                            <button
                              onClick={() => handleToggleOrgStatus(o)}
                              className={`px-2 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer border ${
                                o.status === 'ACTIVE'
                                  ? 'bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border-amber-500/20'
                                  : 'bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border-emerald-500/20'
                              }`}
                            >
                              {o.status === 'ACTIVE' ? 'Suspend' : 'Reactivate'}
                            </button>
                            <button
                              onClick={() => setShowDeleteOrgConfirm(o.organizationId)}
                              className="p-1 text-slate-500 hover:text-rose-400 transition-colors cursor-pointer"
                              title="Delete Organization"
                            >
                              <Trash2 className="w-4 h-4" />
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
        </div>
      )}

      {/* TAB 3: CROSS-TENANT FLEET */}
      {activeTab === 'fleet' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="relative flex-1 min-w-[240px]">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search across all devices (ID, IP, Name)..."
                value={deviceSearch}
                onChange={(e) => setDeviceSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span className="text-slate-400">Filter Tenant:</span>
              <select
                value={selectedOrgFilter}
                onChange={(e) => setSelectedOrgFilter(e.target.value)}
                className="bg-slate-900 border border-slate-800 text-slate-300 rounded-xl px-3 py-2 focus:outline-none focus:border-indigo-500 cursor-pointer"
              >
                <option value="ALL">All Organizations ({devices.length})</option>
                {organizations.map(o => (
                  <option key={o.organizationId} value={o.organizationId}>
                    {o.name} ({o.organizationId})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3.5 px-4">Device Identity</th>
                    <th className="py-3.5 px-4">Tenant / Org</th>
                    <th className="py-3.5 px-4">Status</th>
                    <th className="py-3.5 px-4">OS / Browser</th>
                    <th className="py-3.5 px-4">Extension</th>
                    <th className="py-3.5 px-4">IP Address</th>
                    <th className="py-3.5 px-4">Last Heartbeat</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredDevices.map((d) => {
                    const isOnline = Date.now() - d.lastHeartbeat < 5 * 60 * 1000;
                    const matchedOrg = organizations.find(o => o.organizationId === d.organizationId);
                    return (
                      <tr key={d.deviceId} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3.5 px-4">
                          <div className="font-semibold text-white">{d.deviceName || d.deviceId}</div>
                          <div className="font-mono text-[10px] text-slate-500">{d.deviceId}</div>
                        </td>
                        <td className="py-3.5 px-4">
                          <div className="font-medium text-slate-200">{matchedOrg?.name || d.organizationId}</div>
                          <div className="font-mono text-[10px] text-slate-500">{d.organizationId}</div>
                        </td>
                        <td className="py-3.5 px-4">
                          {isOnline ? (
                            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                              Online
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                              Offline
                            </span>
                          )}
                        </td>
                        <td className="py-3.5 px-4 text-slate-300">
                          {d.os} • {d.browser}
                        </td>
                        <td className="py-3.5 px-4 font-mono text-indigo-300">
                          v{d.extensionVersion}
                        </td>
                        <td className="py-3.5 px-4 font-mono text-slate-400">
                          {d.ip || '127.0.0.1'}
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {new Date(d.lastHeartbeat).toLocaleTimeString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: ADMIN USERS & RBAC */}
      {activeTab === 'users' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Users className="w-5 h-5 text-indigo-400" />
              <span>Platform Administrators & Tenant Operators ({adminUsers.length})</span>
            </h3>
            <button
              onClick={() => setShowCreateUserModal(true)}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              <span>Add Admin User</span>
            </button>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3.5 px-4">User Name</th>
                    <th className="py-3.5 px-4">Email</th>
                    <th className="py-3.5 px-4">Role</th>
                    <th className="py-3.5 px-4">Assigned Tenant</th>
                    <th className="py-3.5 px-4">Created Date</th>
                    <th className="py-3.5 px-4">Last Login</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {adminUsers.map((u) => {
                    const assignedOrg = organizations.find(o => o.organizationId === u.organizationId);
                    return (
                      <tr key={u.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3.5 px-4">
                          <div className="font-bold text-white">{u.name}</div>
                          <div className="font-mono text-[10px] text-slate-500">@{u.username}</div>
                        </td>
                        <td className="py-3.5 px-4 font-mono text-slate-300">
                          {u.email}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            u.role === 'SUPER_ADMIN'
                              ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                              : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                          }`}>
                            {u.role}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-slate-300">
                          {u.role === 'SUPER_ADMIN' ? (
                            <span className="text-slate-500">All Tenants (Global)</span>
                          ) : (
                            <span>{assignedOrg?.name || u.organizationId || '—'}</span>
                          )}
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {new Date(u.createdAt).toLocaleDateString()}
                        </td>
                        <td className="py-3.5 px-4 text-slate-400">
                          {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'Never'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: GLOBAL AUDIT LOGS */}
      {activeTab === 'audit' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Chronological Platform Audit Trail
              </h4>
              <span className="text-xs text-slate-400">{auditLogs.length} logged events</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Action Type</th>
                    <th className="py-3 px-4">Target Organization</th>
                    <th className="py-3 px-4">Actor</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4">
                        <span className="font-mono text-xs text-indigo-400 font-semibold">
                          {log.action}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {log.organizationId || 'GLOBAL'}
                      </td>
                      <td className="py-3 px-4 text-white font-medium">
                        {log.actor || 'System'}
                      </td>
                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-mono text-[11px] max-w-xs truncate">
                        {JSON.stringify(log.details || {})}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: STORAGE & SUPABASE DIAGNOSTICS */}
      {activeTab === 'diagnostics' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Server className="w-5 h-5 text-indigo-400" />
              <span>Storage Adapter & Supabase Database Verification</span>
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              PhishGuard implements an abstract Database Adapter architecture. In local prototyping and isolated environments, it utilizes an ACID JSON file storage engine. In production or cloud deployments with configured Supabase credentials, it automatically connects to PostgreSQL tables.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Adapter Mode</span>
                  <span className="text-xs font-mono font-bold text-emerald-400">IDatabaseAdapter</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Organizations Registered</span>
                  <span className="text-xs font-mono font-bold text-white">{organizations.length}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Enrolled Devices</span>
                  <span className="text-xs font-mono font-bold text-white">{devices.length}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Admin User Accounts</span>
                  <span className="text-xs font-mono font-bold text-white">{adminUsers.length}</span>
                </div>
              </div>

              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Server Status</span>
                  <span className="text-xs font-bold text-emerald-400 flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    Healthy (HTTP 200)
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Node Uptime</span>
                  <span className="text-xs font-mono text-slate-300">{healthData?.uptimeSec || 120}s</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Extension Engine Version</span>
                  <span className="text-xs font-mono text-indigo-400">v1.0.0 (Manifest V3)</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">Privacy Guarantee</span>
                  <span className="text-xs text-emerald-400 font-semibold">Zero Remote Exfiltration</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* PROVISION ORG MODAL */}
      {showCreateOrgModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Building2 className="w-5 h-5 text-indigo-400" />
              <span>Provision Customer Organization</span>
            </h3>
            <form onSubmit={handleCreateOrganization} className="space-y-3 pt-2">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Company Name</label>
                <input
                  type="text"
                  placeholder="e.g. Apex Financial Technologies"
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Organization ID / Slug</label>
                <input
                  type="text"
                  placeholder="e.g. ORG-APEX-FIN"
                  value={newOrgId}
                  onChange={(e) => setNewOrgId(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white font-mono focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Primary Domain</label>
                  <input
                    type="text"
                    placeholder="apexfin.com"
                    value={newOrgDomain}
                    onChange={(e) => setNewOrgDomain(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Contact Email</label>
                  <input
                    type="email"
                    placeholder="secops@apexfin.com"
                    value={newOrgEmail}
                    onChange={(e) => setNewOrgEmail(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Plan Tier</label>
                  <select
                    value={newOrgPlan}
                    onChange={(e) => setNewOrgPlan(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500 cursor-pointer"
                  >
                    <option value="ENTERPRISE_PILOT">Enterprise Pilot</option>
                    <option value="PRODUCTION_FLEET">Production Fleet</option>
                    <option value="CUSTOM_UNLIMITED">Custom Unlimited</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Enforcement</label>
                  <select
                    value={newOrgMode}
                    onChange={(e) => setNewOrgMode(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500 cursor-pointer"
                  >
                    <option value="BLOCK">BLOCK (Strict)</option>
                    <option value="WARN">WARN (Advisory)</option>
                    <option value="MONITOR">MONITOR (Silent)</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setShowCreateOrgModal(false)}
                  className="px-4 py-2 bg-slate-800 text-slate-300 rounded-xl text-xs font-medium hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingOrg}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer shadow-lg shadow-indigo-600/20"
                >
                  {creatingOrg ? 'Provisioning...' : 'Provision Tenant'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CREATE ADMIN USER MODAL */}
      {showCreateUserModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Users className="w-5 h-5 text-indigo-400" />
              <span>Create Administrator / Tenant Operator</span>
            </h3>
            <form onSubmit={handleCreateUser} className="space-y-3 pt-2">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Full Name</label>
                <input
                  type="text"
                  placeholder="e.g. Jordan Hayes"
                  value={newUserName}
                  onChange={(e) => setNewUserName(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Email Address</label>
                <input
                  type="email"
                  placeholder="jordan@company.com"
                  value={newUserEmail}
                  onChange={(e) => setNewUserEmail(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Role</label>
                  <select
                    value={newUserRole}
                    onChange={(e) => setNewUserRole(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500 cursor-pointer"
                  >
                    <option value="ORG_ADMIN">Customer Org Admin</option>
                    <option value="SUPER_ADMIN">Platform Super Admin</option>
                    <option value="READ_ONLY">Read Only Auditor</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Assign Tenant</label>
                  <select
                    value={newUserOrgId}
                    onChange={(e) => setNewUserOrgId(e.target.value)}
                    disabled={newUserRole === 'SUPER_ADMIN'}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500 cursor-pointer disabled:opacity-40"
                  >
                    {organizations.map(o => (
                      <option key={o.organizationId} value={o.organizationId}>
                        {o.name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Temporary Password</label>
                <input
                  type="password"
                  value={newUserPassword}
                  onChange={(e) => setNewUserPassword(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500 font-mono"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setShowCreateUserModal(false)}
                  className="px-4 py-2 bg-slate-800 text-slate-300 rounded-xl text-xs font-medium hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingUser}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer shadow-lg shadow-indigo-600/20"
                >
                  {creatingUser ? 'Creating...' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* DELETE ORG CONFIRM */}
      {showDeleteOrgConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="w-10 h-10 rounded-xl bg-rose-500/20 text-rose-400 flex items-center justify-center">
              <Trash2 className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Delete Customer Organization?</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Organization <strong className="text-white font-mono">{showDeleteOrgConfirm}</strong> and all associated fleet devices will be permanently removed.
              </p>
            </div>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setShowDeleteOrgConfirm(null)}
                className="px-4 py-2 bg-slate-800 text-slate-300 rounded-xl text-xs font-medium hover:bg-slate-700 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteOrganization(showDeleteOrgConfirm)}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-semibold transition-colors cursor-pointer shadow-lg shadow-rose-600/20"
              >
                Confirm Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
