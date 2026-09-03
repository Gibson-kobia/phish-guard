import React from 'react';
import {
  X,
  Laptop,
  Clock,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Activity,
  CheckCircle2,
  Calendar,
  Layers,
  ArrowRight
} from 'lucide-react';
import { EnrolledDevice, CanonicalSecurityEvent } from '../../core/types';

interface DeviceDetailDrawerProps {
  device: EnrolledDevice | null;
  events: CanonicalSecurityEvent[];
  onClose: () => void;
  onSelectEvent?: (event: CanonicalSecurityEvent) => void;
}

export const DeviceDetailDrawer: React.FC<DeviceDetailDrawerProps> = ({
  device,
  events,
  onClose,
  onSelectEvent
}) => {
  if (!device) return null;

  const statusBadge =
    device.status === 'ONLINE'
      ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900/60'
      : device.status === 'UPDATE_REQUIRED'
      ? 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-900/60'
      : 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700';

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
    <div className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-xs">
      <div className="flex h-full w-full max-w-xl flex-col bg-white shadow-2xl dark:bg-slate-900">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-200 px-6 py-4 dark:border-slate-800">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-50 text-blue-600 dark:bg-blue-950/50 dark:text-blue-400">
              <Laptop className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-mono text-sm font-bold text-slate-900 dark:text-slate-100">
                  {device.deviceId}
                </h3>
                <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${statusBadge}`}>
                  {device.status}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">{device.deviceName}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-200"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 space-y-6 overflow-y-auto p-6 text-sm">
          {/* Device Profile Specs */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="text-xs text-slate-500 dark:text-slate-400">Operating System</div>
              <div className="mt-1 font-semibold text-slate-900 dark:text-slate-100">{device.os}</div>
            </div>

            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="text-xs text-slate-500 dark:text-slate-400">Browser Environment</div>
              <div className="mt-1 font-semibold text-slate-900 dark:text-slate-100">{device.browser}</div>
            </div>

            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="text-xs text-slate-500 dark:text-slate-400">Extension Version</div>
              <div className="mt-1 font-mono font-semibold text-slate-900 dark:text-slate-100">
                v{device.extensionVersion}
              </div>
            </div>

            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="text-xs text-slate-500 dark:text-slate-400">Last Active</div>
              <div className="mt-1 font-semibold text-slate-900 dark:text-slate-100">
                {timeAgo(device.lastSeen)}
              </div>
            </div>

            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="text-xs text-slate-500 dark:text-slate-400">Enrolled Date</div>
              <div className="mt-1 text-xs font-semibold text-slate-900 dark:text-slate-100">
                {new Date(device.firstSeen).toLocaleDateString()}
              </div>
            </div>

            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="text-xs text-slate-500 dark:text-slate-400">Organization</div>
              <div className="mt-1 font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">
                {device.organizationId}
              </div>
            </div>
          </div>

          {/* Protection Stats on this endpoint */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-4 dark:border-slate-800 dark:bg-slate-950/40">
            <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Endpoint Protection Stats
            </h4>
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="rounded-lg bg-white p-3 shadow-xs dark:bg-slate-900">
                <div className="text-lg font-bold text-slate-900 dark:text-slate-100">
                  {device.eventsCount}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Total Scans</div>
              </div>
              <div className="rounded-lg bg-white p-3 shadow-xs dark:bg-slate-900">
                <div className="text-lg font-bold text-rose-600 dark:text-rose-400">
                  {device.blockedCount}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Threats Blocked</div>
              </div>
              <div className="rounded-lg bg-white p-3 shadow-xs dark:bg-slate-900">
                <div className="text-lg font-bold text-amber-500">
                  {device.warningsCount}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Warnings</div>
              </div>
            </div>
          </div>

          {/* Recent Security Events on this device */}
          <div>
            <div className="mb-3 flex items-center justify-between">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Recent Security Events ({events.length})
              </h4>
            </div>

            <div className="space-y-2">
              {events.map((evt) => (
                <div
                  key={evt.eventId}
                  onClick={() => onSelectEvent && onSelectEvent(evt)}
                  className="flex cursor-pointer items-center justify-between rounded-lg border border-slate-200 p-3 transition-colors hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/60"
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`h-2.5 w-2.5 rounded-full ${
                        evt.riskScore >= 80
                          ? 'bg-rose-500'
                          : evt.riskScore >= 40
                          ? 'bg-amber-500'
                          : 'bg-emerald-500'
                      }`}
                    />
                    <div>
                      <div className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">
                        {evt.hostname}
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400">
                        {evt.action} • {timeAgo(evt.timestamp)}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-slate-700 dark:text-slate-300">
                      {evt.riskScore}/100
                    </span>
                    <ArrowRight className="h-3.5 w-3.5 text-slate-400" />
                  </div>
                </div>
              ))}

              {events.length === 0 && (
                <div className="rounded-lg border border-dashed border-slate-200 p-6 text-center text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  No security events recorded for this device yet.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-slate-200 px-6 py-3 dark:border-slate-800">
          <button
            onClick={onClose}
            className="w-full rounded-lg border border-slate-300 bg-white py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
          >
            Close Device Details
          </button>
        </div>
      </div>
    </div>
  );
};
