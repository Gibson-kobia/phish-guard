import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Laptop,
  Radio,
  ExternalLink,
  ChevronRight,
  TrendingUp,
  Tag,
  Clock,
  ArrowUpRight
} from 'lucide-react';
import { CanonicalSecurityEvent } from '../../core/types';

interface CompanyOverviewProps {
  stats: {
    threatsToday: number;
    blockedToday: number;
    warningsToday: number;
    totalProtectedDevices: number;
    onlineDevices: number;
    offlineDevices: number;
    updateRequiredDevices: number;
    devicesNeedingAttention: number;
    currentExtensionVersion: string;
    minExtensionVersion: string;
    enforcementMode: string;
    topTargetedBrands: Array<{ brand: string; count: number }>;
    topThreatCategories: Array<{ category: string; count: number }>;
    recentEvents: CanonicalSecurityEvent[];
  };
  onSelectEvent: (event: CanonicalSecurityEvent) => void;
  onNavigateTab: (tab: 'events' | 'devices' | 'reports' | 'settings') => void;
}

export const CompanyOverview: React.FC<CompanyOverviewProps> = ({
  stats,
  onSelectEvent,
  onNavigateTab
}) => {
  const timeAgo = (timestamp: number) => {
    const diffSec = Math.floor((Date.now() - timestamp) / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${Math.floor(diffHours / 24)}d ago`;
  };

  return (
    <div className="space-y-6">
      {/* Top Level Metric Cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Threats Today */}
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Threats Intercepted (24h)</span>
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-rose-50 text-rose-600 dark:bg-rose-950/40 dark:text-rose-400">
              <ShieldAlert className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-900 dark:text-slate-100">
            {stats.threatsToday}
          </div>
          <div className="mt-1 flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
            <span className="font-semibold text-rose-600 dark:text-rose-400">{stats.blockedToday} blocked</span>
            <span>•</span>
            <span className="font-semibold text-amber-500">{stats.warningsToday} warned</span>
          </div>
        </div>

        {/* Protected Fleet */}
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Protected Endpoints</span>
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-blue-50 text-blue-600 dark:bg-blue-950/40 dark:text-blue-400">
              <Laptop className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-900 dark:text-slate-100">
            {stats.totalProtectedDevices}
          </div>
          <div className="mt-1 flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
            <span className="font-semibold text-emerald-600">{stats.onlineDevices} online</span>
            <span>•</span>
            <span>{stats.offlineDevices} offline</span>
          </div>
        </div>

        {/* Devices Needing Attention */}
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Fleet Health Status</span>
            <div
              className={`flex h-7 w-7 items-center justify-center rounded-lg ${
                stats.devicesNeedingAttention > 0
                  ? 'bg-amber-50 text-amber-600 dark:bg-amber-950/40 dark:text-amber-400'
                  : 'bg-emerald-50 text-emerald-600 dark:bg-emerald-950/40 dark:text-emerald-400'
              }`}
            >
              {stats.devicesNeedingAttention > 0 ? (
                <AlertTriangle className="h-4 w-4" />
              ) : (
                <ShieldCheck className="h-4 w-4" />
              )}
            </div>
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-900 dark:text-slate-100">
            {stats.devicesNeedingAttention === 0 ? 'Optimal' : `${stats.devicesNeedingAttention} Outdated`}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {stats.updateRequiredDevices > 0
              ? `${stats.updateRequiredDevices} need v${stats.minExtensionVersion} update`
              : 'All active agents compliant'}
          </div>
        </div>

        {/* Policy Enforcement Mode */}
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Enforcement Policy</span>
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600 dark:bg-indigo-950/40 dark:text-indigo-400">
              <Radio className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-900 dark:text-slate-100">
            {stats.enforcementMode}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Strict navigation block for score ≥ 80
          </div>
        </div>
      </div>

      {/* Main Grid: Recent Threats & Threat Distributions */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Recent Real Security Events Table (2 Cols) */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs dark:border-slate-800 dark:bg-slate-900 lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                Recent Security Events
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Real-time browser threat interceptions from connected endpoints
              </p>
            </div>
            <button
              onClick={() => onNavigateTab('events')}
              className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-700 dark:text-blue-400"
            >
              View All Events
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="divide-y divide-slate-100 overflow-hidden rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
            {stats.recentEvents.slice(0, 6).map((evt) => (
              <div
                key={evt.eventId}
                onClick={() => onSelectEvent(evt)}
                className="flex cursor-pointer items-center justify-between p-3.5 transition-colors hover:bg-slate-50/80 dark:hover:bg-slate-800/50"
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg font-mono text-xs font-bold ${
                      evt.riskScore >= 80
                        ? 'bg-rose-50 text-rose-700 dark:bg-rose-950/40 dark:text-rose-400'
                        : evt.riskScore >= 40
                        ? 'bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-400'
                        : 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-400'
                    }`}
                  >
                    {evt.riskScore}
                  </span>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">
                        {evt.hostname}
                      </span>
                      {evt.brand && (
                        <span className="rounded bg-slate-100 px-1.5 py-0.2 text-[10px] font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                          {evt.brand} Spoof
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {evt.action} on {evt.deviceId} • {timeAgo(evt.timestamp)}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${
                      evt.action === 'BLOCKED' || evt.navigationBlocked
                        ? 'bg-rose-100 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300'
                        : evt.action === 'WARNED'
                        ? 'bg-amber-100 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300'
                        : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300'
                    }`}
                  >
                    {evt.action}
                  </span>
                  <ArrowUpRight className="h-3.5 w-3.5 text-slate-400" />
                </div>
              </div>
            ))}

            {stats.recentEvents.length === 0 && (
              <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                No security events observed yet. Endpoint browsers are quiet.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Top Targeted Brands & Categories */}
        <div className="space-y-6">
          {/* Top Targeted Brands */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
              Top Impersonated Brands
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Brands actively targeted in employee phishing attempts
            </p>

            <div className="mt-4 space-y-3">
              {stats.topTargetedBrands.map((item) => (
                <div key={item.brand} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-800 dark:text-slate-200">{item.brand}</span>
                  </div>
                  <span className="rounded-full bg-slate-100 px-2 py-0.5 font-mono text-[11px] font-bold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                    {item.count} attacks
                  </span>
                </div>
              ))}

              {stats.topTargetedBrands.length === 0 && (
                <div className="py-4 text-center text-xs text-slate-500 dark:text-slate-400">
                  No brand impersonations recorded.
                </div>
              )}
            </div>
          </div>

          {/* Threat Categories Breakdown */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
              Threat Vectors
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Distribution across detection heuristics
            </p>

            <div className="mt-4 space-y-2.5">
              {stats.topThreatCategories.map((cat) => (
                <div key={cat.category} className="flex items-center justify-between text-xs">
                  <span className="text-slate-700 dark:text-slate-300">{cat.category}</span>
                  <span className="font-mono text-slate-500 dark:text-slate-400">{cat.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
