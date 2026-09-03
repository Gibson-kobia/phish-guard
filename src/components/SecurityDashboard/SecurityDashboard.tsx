import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Search,
  Filter,
  Download,
  Terminal,
  ExternalLink,
  ChevronRight,
  Database,
  Building2,
  Users,
  Clock,
  RefreshCw,
  Eye,
  Lock,
  Globe,
  Radio,
  FileSpreadsheet,
  Layers,
  Send,
  SlidersHorizontal,
  Laptop
} from 'lucide-react';
import {
  CanonicalSecurityEvent,
  EnrolledDevice,
  Organization
} from '../../core/types';
import { CompanyOverview } from './CompanyOverview';
import { SecurityEventsView } from './SecurityEventsView';
import { FleetDevicesView } from './FleetDevicesView';
import { ReportsView } from './ReportsView';
import { SettingsPoliciesView } from './SettingsPoliciesView';
import { AuditLogView } from './AuditLogView';
import { EventDetailModal } from './EventDetailModal';
import { DeviceDetailDrawer } from './DeviceDetailDrawer';
import { PipelineSimulator } from './PipelineSimulator';

type DashboardTab = 'overview' | 'events' | 'devices' | 'reports' | 'settings' | 'audit' | 'pipeline';

interface SecurityDashboardProps {
  onInspectUrl?: (url: string) => void;
}

export const SecurityDashboard: React.FC<SecurityDashboardProps> = ({ onInspectUrl }) => {
  const [activeTab, setActiveTab] = useState<DashboardTab>('overview');
  const [isServerConnected, setIsServerConnected] = useState(true);

  // Data state
  const [overviewStats, setOverviewStats] = useState<any>({
    threatsToday: 0,
    blockedToday: 0,
    warningsToday: 0,
    totalProtectedDevices: 0,
    onlineDevices: 0,
    offlineDevices: 0,
    updateRequiredDevices: 0,
    devicesNeedingAttention: 0,
    currentExtensionVersion: '1.0.0',
    minExtensionVersion: '1.0.0',
    enforcementMode: 'BLOCK',
    topTargetedBrands: [],
    topThreatCategories: [],
    recentEvents: []
  });

  const [events, setEvents] = useState<CanonicalSecurityEvent[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 25;

  // Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState<'newest' | 'highest_risk'>('newest');

  // Fleet state
  const [devices, setDevices] = useState<EnrolledDevice[]>([]);
  const [organization, setOrganization] = useState<Organization | null>(null);

  // Selected modals/drawers
  const [selectedEvent, setSelectedEvent] = useState<CanonicalSecurityEvent | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<EnrolledDevice | null>(null);
  const [selectedDeviceEvents, setSelectedDeviceEvents] = useState<CanonicalSecurityEvent[]>([]);

  // Fetch Overview Stats
  const fetchOverview = async () => {
    try {
      const res = await fetch('/api/overview');
      if (res.ok) {
        const data = await res.json();
        setOverviewStats(data);
        setIsServerConnected(true);
      }
    } catch {
      setIsServerConnected(false);
    }
  };

  // Fetch Events with pagination & filters
  const fetchEvents = async () => {
    try {
      const params = new URLSearchParams();
      if (searchQuery) params.set('search', searchQuery);
      if (riskFilter !== 'ALL') params.set('riskLevel', riskFilter);
      if (actionFilter !== 'ALL') params.set('action', actionFilter);
      if (categoryFilter !== 'ALL') params.set('threatCategory', categoryFilter);
      params.set('sortBy', sortBy);
      params.set('page', String(currentPage));
      params.set('pageSize', String(pageSize));

      const res = await fetch(`/api/events?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events || []);
        setTotalEvents(data.total || 0);
      }
    } catch {}
  };

  // Fetch Fleet Devices & Org Config
  const fetchFleet = async () => {
    try {
      const [devRes, orgRes] = await Promise.all([
        fetch('/api/devices'),
        fetch('/api/organizations')
      ]);

      if (devRes.ok) {
        const devData = await devRes.json();
        setDevices(devData.devices || []);
      }
      if (orgRes.ok) {
        const orgData = await orgRes.json();
        if (orgData.organizations && orgData.organizations.length > 0) {
          setOrganization(orgData.organizations[0]);
        }
      }
    } catch {}
  };

  useEffect(() => {
    fetchOverview();
    fetchFleet();
  }, []);

  useEffect(() => {
    fetchEvents();
  }, [searchQuery, riskFilter, actionFilter, categoryFilter, sortBy, currentPage]);

  const handleSelectDevice = async (device: EnrolledDevice) => {
    setSelectedDevice(device);
    try {
      const res = await fetch(`/api/devices/${device.deviceId}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedDeviceEvents(data.events || []);
      }
    } catch {
      setSelectedDeviceEvents([]);
    }
  };

  const handleUpdateOrganization = async (updates: Partial<Organization>) => {
    if (!organization) return;
    try {
      const res = await fetch(`/api/organizations/${organization.organizationId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...updates, actor: 'Security Console Admin' })
      });
      if (res.ok) {
        const data = await res.json();
        setOrganization(data.organization);
        fetchOverview();
      }
    } catch {}
  };

  const handleExportCsv = () => {
    window.location.href = '/api/reports/export-csv';
  };

  return (
    <div className="flex min-h-[calc(100vh-4rem)] flex-col bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      {/* Enterprise Top Banner */}
      <div className="border-b border-slate-200 bg-white px-6 py-4 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-600 text-white shadow-xs">
              <Shield className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  PhishGuard Enterprise Security Platform
                </h1>
                <span className="rounded-full bg-blue-50 px-2 py-0.5 text-[11px] font-bold text-blue-700 border border-blue-200 dark:bg-blue-950/50 dark:text-blue-300 dark:border-blue-900">
                  v1.0.0 Pilot
                </span>
                <span className="flex items-center gap-1.5 rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 border border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  Live Sync
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Organization: <span className="font-semibold text-slate-700 dark:text-slate-300">{organization?.name || 'Acme Corporation (Security Pilot)'}</span> • ID: <span className="font-mono">{organization?.organizationId || 'ORG-ACME-PILOT'}</span>
              </p>
            </div>
          </div>

          {/* Quick Stats in Top Right */}
          <div className="flex items-center gap-4 text-xs">
            <div className="text-right">
              <div className="font-bold text-slate-900 dark:text-slate-100">
                {overviewStats.totalProtectedDevices} Endpoints Protected
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">
                {overviewStats.onlineDevices} Online • {overviewStats.threatsToday} Threats Intercepted Today
              </div>
            </div>
            <button
              onClick={() => {
                fetchOverview();
                fetchEvents();
                fetchFleet();
              }}
              className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
              title="Refresh Data"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="mt-4 flex flex-wrap gap-1 border-t border-slate-100 pt-3 dark:border-slate-800/80">
          <button
            onClick={() => setActiveTab('overview')}
            className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors ${
              activeTab === 'overview'
                ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
            }`}
          >
            Overview
          </button>

          <button
            onClick={() => setActiveTab('events')}
            className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors ${
              activeTab === 'events'
                ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
            }`}
          >
            Security Events ({totalEvents})
          </button>

          <button
            onClick={() => setActiveTab('devices')}
            className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors ${
              activeTab === 'devices'
                ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
            }`}
          >
            Fleet Devices ({devices.length})
          </button>

          <button
            onClick={() => setActiveTab('reports')}
            className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors ${
              activeTab === 'reports'
                ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
            }`}
          >
            Reports & CSV
          </button>

          <button
            onClick={() => setActiveTab('settings')}
            className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors ${
              activeTab === 'settings'
                ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
            }`}
          >
            Settings & Policy
          </button>

          <button
            onClick={() => setActiveTab('audit')}
            className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors ${
              activeTab === 'audit'
                ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
            }`}
          >
            Audit Log
          </button>

          <button
            onClick={() => setActiveTab('pipeline')}
            className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-colors ${
              activeTab === 'pipeline'
                ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
            }`}
          >
            Pipeline Architecture
          </button>
        </div>
      </div>

      {/* Main Tab Views */}
      <div className="flex-1 p-6">
        {activeTab === 'overview' && (
          <CompanyOverview
            stats={overviewStats}
            onSelectEvent={(evt) => setSelectedEvent(evt)}
            onNavigateTab={(tab) => setActiveTab(tab)}
          />
        )}

        {activeTab === 'events' && (
          <SecurityEventsView
            events={events}
            total={totalEvents}
            currentPage={currentPage}
            pageSize={pageSize}
            searchQuery={searchQuery}
            riskFilter={riskFilter}
            actionFilter={actionFilter}
            categoryFilter={categoryFilter}
            sortBy={sortBy}
            onSearchChange={(q) => {
              setSearchQuery(q);
              setCurrentPage(1);
            }}
            onRiskFilterChange={(r) => {
              setRiskFilter(r);
              setCurrentPage(1);
            }}
            onActionFilterChange={(a) => {
              setActionFilter(a);
              setCurrentPage(1);
            }}
            onCategoryFilterChange={(c) => {
              setCategoryFilter(c);
              setCurrentPage(1);
            }}
            onSortByChange={(s) => setSortBy(s)}
            onPageChange={(p) => setCurrentPage(p)}
            onSelectEvent={(evt) => setSelectedEvent(evt)}
            onExportCsv={handleExportCsv}
          />
        )}

        {activeTab === 'devices' && (
          <FleetDevicesView
            devices={devices}
            organization={organization}
            onSelectDevice={(d) => handleSelectDevice(d)}
            onRefresh={() => fetchFleet()}
          />
        )}

        {activeTab === 'reports' && (
          <ReportsView onExportCsv={handleExportCsv} />
        )}

        {activeTab === 'settings' && (
          <SettingsPoliciesView
            organization={organization}
            onUpdateOrganization={handleUpdateOrganization}
          />
        )}

        {activeTab === 'audit' && <AuditLogView />}

        {activeTab === 'pipeline' && <PipelineSimulator />}
      </div>

      {/* Selected Event Detail Modal */}
      {selectedEvent && (
        <EventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          onInspectUrl={onInspectUrl}
        />
      )}

      {/* Selected Device Detail Drawer */}
      {selectedDevice && (
        <DeviceDetailDrawer
          device={selectedDevice}
          events={selectedDeviceEvents}
          onClose={() => setSelectedDevice(null)}
          onSelectEvent={(evt) => {
            setSelectedDevice(null);
            setSelectedEvent(evt);
          }}
        />
      )}
    </div>
  );
};
