import React, { useState } from 'react';
import {
  Search,
  Filter,
  ArrowUpDown,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Download,
  ExternalLink,
  Laptop
} from 'lucide-react';
import { CanonicalSecurityEvent } from '../../core/types';

interface SecurityEventsViewProps {
  events: CanonicalSecurityEvent[];
  total: number;
  currentPage: number;
  pageSize: number;
  searchQuery: string;
  riskFilter: string;
  actionFilter: string;
  categoryFilter: string;
  sortBy: 'newest' | 'highest_risk';
  onSearchChange: (q: string) => void;
  onRiskFilterChange: (val: string) => void;
  onActionFilterChange: (val: string) => void;
  onCategoryFilterChange: (val: string) => void;
  onSortByChange: (sort: 'newest' | 'highest_risk') => void;
  onPageChange: (page: number) => void;
  onSelectEvent: (event: CanonicalSecurityEvent) => void;
  onExportCsv: () => void;
}

export const SecurityEventsView: React.FC<SecurityEventsViewProps> = ({
  events,
  total,
  currentPage,
  pageSize,
  searchQuery,
  riskFilter,
  actionFilter,
  categoryFilter,
  sortBy,
  onSearchChange,
  onRiskFilterChange,
  onActionFilterChange,
  onCategoryFilterChange,
  onSortByChange,
  onPageChange,
  onSelectEvent,
  onExportCsv
}) => {
  const totalPages = Math.ceil(total / pageSize) || 1;

  const getRiskBadge = (score: number, level: string) => {
    if (score >= 80 || level === 'CRITICAL') {
      return 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/40 dark:text-rose-400 dark:border-rose-900/60';
    }
    if (score >= 60 || level === 'HIGH') {
      return 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-900/60';
    }
    if (score >= 35 || level === 'MEDIUM') {
      return 'bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-950/40 dark:text-yellow-400 dark:border-yellow-900/60';
    }
    return 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900/60';
  };

  const getActionBadge = (action: string, blocked: boolean) => {
    if (action === 'BLOCKED' || blocked) {
      return 'bg-rose-600 text-white';
    }
    if (action === 'WARNED') {
      return 'bg-amber-500 text-white';
    }
    return 'bg-emerald-600 text-white';
  };

  return (
    <div className="space-y-4">
      {/* Search & Filters Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <div className="flex flex-1 flex-wrap items-center gap-2.5">
          {/* Search Input */}
          <div className="relative min-w-[240px] flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search hostname, URL, brand, reason, device ID..."
              className="w-full rounded-lg border border-slate-200 bg-slate-50/50 py-2 pl-9 pr-3 text-xs text-slate-900 focus:border-blue-500 focus:bg-white focus:outline-hidden dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100 dark:focus:border-blue-500"
            />
          </div>

          {/* Risk Filter */}
          <select
            value={riskFilter}
            onChange={(e) => onRiskFilterChange(e.target.value)}
            className="rounded-lg border border-slate-200 bg-slate-50/50 px-2.5 py-2 text-xs font-medium text-slate-700 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300"
          >
            <option value="ALL">All Risk Tiers</option>
            <option value="CRITICAL">Critical (80-100)</option>
            <option value="HIGH">High (60-79)</option>
            <option value="MEDIUM">Medium (35-59)</option>
            <option value="LOW">Low (15-34)</option>
            <option value="SAFE">Safe (0-14)</option>
          </select>

          {/* Action Filter */}
          <select
            value={actionFilter}
            onChange={(e) => onActionFilterChange(e.target.value)}
            className="rounded-lg border border-slate-200 bg-slate-50/50 px-2.5 py-2 text-xs font-medium text-slate-700 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300"
          >
            <option value="ALL">All Actions</option>
            <option value="BLOCKED">Blocked</option>
            <option value="WARNED">Warned</option>
            <option value="ALLOWED">Allowed</option>
            <option value="USER_OVERRIDE">User Override</option>
          </select>

          {/* Sort By */}
          <button
            onClick={() => onSortByChange(sortBy === 'newest' ? 'highest_risk' : 'newest')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50/50 px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            <ArrowUpDown className="h-3.5 w-3.5" />
            <span>Sort: {sortBy === 'newest' ? 'Newest' : 'Highest Risk'}</span>
          </button>
        </div>

        {/* CSV Export Button */}
        <button
          onClick={onExportCsv}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
        >
          <Download className="h-3.5 w-3.5" />
          Export CSV
        </button>
      </div>

      {/* Events Table */}
      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-200 bg-slate-50/80 font-semibold text-slate-600 dark:border-slate-800 dark:bg-slate-950/60 dark:text-slate-400">
              <tr>
                <th className="px-4 py-3">Risk Score</th>
                <th className="px-4 py-3">Destination Hostname</th>
                <th className="px-4 py-3">Action Taken</th>
                <th className="px-4 py-3">Threat Category / Brand</th>
                <th className="px-4 py-3">Device Attribution</th>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {events.map((evt) => (
                <tr
                  key={evt.eventId}
                  onClick={() => onSelectEvent(evt)}
                  className="cursor-pointer transition-colors hover:bg-slate-50/80 dark:hover:bg-slate-800/40"
                >
                  <td className="px-4 py-3.5">
                    <span
                      className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-xs font-bold ${getRiskBadge(
                        evt.riskScore,
                        evt.riskLevel
                      )}`}
                    >
                      {evt.riskScore}/100
                    </span>
                  </td>

                  <td className="px-4 py-3.5">
                    <div className="max-w-xs truncate font-mono font-semibold text-slate-900 dark:text-slate-100">
                      {evt.hostname}
                    </div>
                    <div className="max-w-xs truncate text-[11px] text-slate-500 dark:text-slate-400">
                      {evt.detectionReasons[0] || evt.url}
                    </div>
                  </td>

                  <td className="px-4 py-3.5">
                    <span
                      className={`inline-block rounded-full px-2.5 py-0.5 text-[10px] font-bold ${getActionBadge(
                        evt.action,
                        evt.navigationBlocked
                      )}`}
                    >
                      {evt.action}
                    </span>
                  </td>

                  <td className="px-4 py-3.5">
                    <div className="font-semibold text-slate-800 dark:text-slate-200">
                      {evt.threatCategory || 'OTHER'}
                    </div>
                    {evt.brand && (
                      <div className="text-[11px] font-medium text-rose-600 dark:text-rose-400">
                        Target: {evt.brand}
                      </div>
                    )}
                  </td>

                  <td className="px-4 py-3.5">
                    <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                      <Laptop className="h-3.5 w-3.5 text-slate-400" />
                      <span>{evt.deviceId}</span>
                    </div>
                    <div className="text-[10px] text-slate-500 dark:text-slate-400">
                      v{evt.extensionVersion}
                    </div>
                  </td>

                  <td className="px-4 py-3.5 text-slate-500 dark:text-slate-400">
                    <div>{new Date(evt.timestamp).toLocaleTimeString()}</div>
                    <div className="text-[10px]">{new Date(evt.timestamp).toLocaleDateString()}</div>
                  </td>

                  <td className="px-4 py-3.5 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectEvent(evt);
                      }}
                      className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}

              {events.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-xs text-slate-500 dark:text-slate-400">
                    No security events found matching the selected filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="flex items-center justify-between border-t border-slate-200 bg-slate-50/50 px-4 py-3 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-950/40 dark:text-slate-400">
          <div>
            Showing <span className="font-semibold">{events.length}</span> of{' '}
            <span className="font-semibold">{total}</span> events
          </div>
          <div className="flex items-center gap-2">
            <button
              disabled={currentPage <= 1}
              onClick={() => onPageChange(currentPage - 1)}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            >
              <ChevronLeft className="h-3.5 w-3.5" />
              Previous
            </button>
            <span className="font-semibold">
              Page {currentPage} of {totalPages}
            </span>
            <button
              disabled={currentPage >= totalPages}
              onClick={() => onPageChange(currentPage + 1)}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            >
              Next
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
