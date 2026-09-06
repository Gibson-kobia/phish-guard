import React, { useState } from 'react';
import {
  Laptop,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Key,
  Copy,
  Check,
  ChevronRight,
  Shield,
  RefreshCw,
  Search,
  ExternalLink
} from 'lucide-react';
import { EnrolledDevice, Organization } from '../../core/types';

interface FleetDevicesViewProps {
  devices: EnrolledDevice[];
  organization: Organization | null;
  onSelectDevice: (device: EnrolledDevice) => void;
  onRefresh: () => void;
}

export const FleetDevicesView: React.FC<FleetDevicesViewProps> = ({
  devices,
  organization,
  onSelectDevice,
  onRefresh
}) => {
  const [copiedToken, setCopiedToken] = useState(false);
  const [search, setSearch] = useState('');

  const handleCopyToken = () => {
    if (organization?.enrollmentToken) {
      navigator.clipboard.writeText(organization.enrollmentToken);
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    }
  };

  const filtered = devices.filter(
    (d) =>
      d.deviceId.toLowerCase().includes(search.toLowerCase()) ||
      d.deviceName?.toLowerCase().includes(search.toLowerCase()) ||
      d.os.toLowerCase().includes(search.toLowerCase())
  );

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
      {/* Fleet Enrollment Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-blue-200 bg-blue-50/60 p-5 dark:border-blue-900/60 dark:bg-blue-950/30">
        <div>
          <h3 className="text-sm font-bold text-blue-950 dark:text-blue-200">
            Company Fleet Enrollment Token
          </h3>
          <p className="mt-1 text-xs text-blue-800 dark:text-blue-300">
            Distribute this token via Chrome Enterprise Policy (GPO / MDM / Google Workspace Admin) to enroll employee browser extensions.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="rounded-lg border border-blue-300 bg-white px-3 py-1.5 font-mono text-xs font-semibold text-slate-800 dark:border-blue-800 dark:bg-slate-900 dark:text-slate-200">
            {organization?.enrollmentToken || 'pg_enroll_acme_pilot_2026'}
          </div>
          <button
            onClick={handleCopyToken}
            className="inline-flex items-center gap-1 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-700"
          >
            {copiedToken ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
            {copiedToken ? 'Copied' : 'Copy Token'}
          </button>
        </div>
      </div>

      {/* Fleet Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <div className="relative min-w-[260px] flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search device ID, name, OS..."
            className="w-full rounded-lg border border-slate-200 bg-slate-50/50 py-2 pl-9 pr-3 text-xs text-slate-900 focus:border-blue-500 focus:bg-white focus:outline-hidden dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100 dark:focus:border-blue-500"
          />
        </div>

        <button
          onClick={onRefresh}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh Fleet Status
        </button>
      </div>

      {/* Devices Table */}
      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-200 bg-slate-50/80 font-semibold text-slate-600 dark:border-slate-800 dark:bg-slate-950/60 dark:text-slate-400">
              <tr>
                <th className="px-4 py-3">Device ID / Label</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Agent Version</th>
                <th className="px-4 py-3">Operating System</th>
                <th className="px-4 py-3">Last Seen</th>
                <th className="px-4 py-3">Scans</th>
                <th className="px-4 py-3">Blocked</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {filtered.map((dev) => {
                const isOnline = dev.status === 'ONLINE';
                const isOutdated = dev.status === 'UPDATE_REQUIRED';

                return (
                  <tr
                    key={dev.deviceId}
                    onClick={() => onSelectDevice(dev)}
                    className="cursor-pointer transition-colors hover:bg-slate-50/80 dark:hover:bg-slate-800/40"
                  >
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2.5">
                        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                          <Laptop className="h-4 w-4" />
                        </div>
                        <div>
                          <div className="font-mono font-bold text-slate-900 dark:text-slate-100">
                            {dev.deviceId}
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400">
                            {dev.deviceName}
                          </div>
                        </div>
                      </div>
                    </td>

                    <td className="px-4 py-3.5">
                      <span
                        className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-bold ${
                          isOnline
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900/60'
                            : isOutdated
                            ? 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-900/60'
                            : 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700'
                        }`}
                      >
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            isOnline ? 'bg-emerald-500' : isOutdated ? 'bg-amber-500' : 'bg-slate-400'
                          }`}
                        />
                        {dev.status}
                      </span>
                    </td>

                    <td className="px-4 py-3.5">
                      <div className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                        v{dev.extensionVersion}
                      </div>
                      {isOutdated && (
                        <div className="text-[10px] font-medium text-amber-600 dark:text-amber-400">
                          Update Required
                        </div>
                      )}
                    </td>

                    <td className="px-4 py-3.5 text-slate-700 dark:text-slate-300">
                      <div>{dev.os}</div>
                      <div className="text-[10px] text-slate-400">{dev.browser}</div>
                    </td>

                    <td className="px-4 py-3.5 text-slate-500 dark:text-slate-400">
                      {timeAgo(dev.lastSeen)}
                    </td>

                    <td className="px-4 py-3.5 font-mono text-slate-700 dark:text-slate-300">
                      {dev.eventsCount}
                    </td>

                    <td className="px-4 py-3.5">
                      <span
                        className={`font-mono font-bold ${
                          dev.blockedCount > 0
                            ? 'text-rose-600 dark:text-rose-400'
                            : 'text-slate-400'
                        }`}
                      >
                        {dev.blockedCount}
                      </span>
                    </td>

                    <td className="px-4 py-3.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectDevice(dev);
                        }}
                        className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                );
              })}

              {filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-xs text-slate-500 dark:text-slate-400">
                    No devices match the search criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
