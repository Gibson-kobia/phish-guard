import React from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Laptop,
  Clock,
  Tag,
  Hash,
  Activity,
  Layers,
  CheckCircle2,
  FileText
} from 'lucide-react';
import { CanonicalSecurityEvent } from '../../core/types';

interface EventDetailModalProps {
  event: CanonicalSecurityEvent | null;
  onClose: () => void;
  onInspectUrl?: (url: string) => void;
}

export const EventDetailModal: React.FC<EventDetailModalProps> = ({
  event,
  onClose,
  onInspectUrl
}) => {
  if (!event) return null;

  const isCritical = event.riskScore >= 80 || event.riskLevel === 'CRITICAL';
  const isHigh = event.riskScore >= 60 || event.riskLevel === 'HIGH';
  const isMedium = event.riskScore >= 35 || event.riskLevel === 'MEDIUM';

  const riskBadgeColor = isCritical
    ? 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/40 dark:text-rose-400 dark:border-rose-900/60'
    : isHigh
    ? 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-900/60'
    : isMedium
    ? 'bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-950/40 dark:text-yellow-400 dark:border-yellow-900/60'
    : 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900/60';

  const actionBadgeColor =
    event.action === 'BLOCKED' || event.navigationBlocked
      ? 'bg-rose-600 text-white'
      : event.action === 'WARNED'
      ? 'bg-amber-500 text-white'
      : 'bg-emerald-600 text-white';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="relative flex max-h-[90vh] w-full max-w-3xl flex-col rounded-xl border border-slate-200 bg-white shadow-2xl dark:border-slate-800 dark:bg-slate-900">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-200 px-6 py-4 dark:border-slate-800">
          <div className="flex items-center gap-3">
            <div
              className={`flex h-10 w-10 items-center justify-center rounded-lg ${
                isCritical
                  ? 'bg-rose-100 text-rose-600 dark:bg-rose-950/50 dark:text-rose-400'
                  : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'
              }`}
            >
              {isCritical ? <ShieldAlert className="h-5 w-5" /> : <ShieldCheck className="h-5 w-5" />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-mono text-base font-semibold text-slate-900 dark:text-slate-100">
                  {event.hostname}
                </h3>
                <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${actionBadgeColor}`}>
                  {event.action}
                </span>
                <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${riskBadgeColor}`}>
                  {event.riskScore}/100 • {event.riskLevel}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Event ID: <span className="font-mono">{event.eventId}</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-200"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="space-y-6 overflow-y-auto p-6 text-sm">
          {/* URL & Destination */}
          <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-4 dark:border-slate-800 dark:bg-slate-950/50">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Sanitized Target URL
            </div>
            <div className="mt-1 break-all font-mono text-xs text-slate-900 dark:text-slate-100">
              {event.url}
            </div>
            {onInspectUrl && (
              <div className="mt-3 flex gap-2">
                <button
                  onClick={() => {
                    onClose();
                    onInspectUrl(event.url);
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                  Inspect in Analysis Playground
                </button>
              </div>
            )}
          </div>

          {/* Key Attributes Grid */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                <Tag className="h-3.5 w-3.5" /> Threat Category
              </div>
              <div className="mt-1 font-semibold text-slate-900 dark:text-slate-100">
                {event.threatCategory || 'OTHER'}
              </div>
            </div>

            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                <ShieldCheck className="h-3.5 w-3.5" /> Target Brand
              </div>
              <div className="mt-1 font-semibold text-slate-900 dark:text-slate-100">
                {event.brand || 'None Detected'}
              </div>
            </div>

            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                <Laptop className="h-3.5 w-3.5" /> Device Identifier
              </div>
              <div className="mt-1 font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">
                {event.deviceId}
              </div>
            </div>

            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                <Clock className="h-3.5 w-3.5" /> Event Timestamp
              </div>
              <div className="mt-1 text-xs font-semibold text-slate-900 dark:text-slate-100">
                {new Date(event.timestamp).toLocaleString()}
              </div>
            </div>
          </div>

          {/* Primary Detection Reasons */}
          <div>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Detection Reasons ({event.detectionReasons.length})
            </h4>
            <div className="space-y-1.5">
              {event.detectionReasons.map((reason, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50/50 p-2.5 text-xs text-slate-800 dark:border-slate-800 dark:bg-slate-950/40 dark:text-slate-200"
                >
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" />
                  <span>{reason}</span>
                </div>
              ))}
              {event.detectionReasons.length === 0 && (
                <div className="flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50/50 p-2.5 text-xs text-emerald-800 dark:border-emerald-900/40 dark:bg-emerald-950/20 dark:text-emerald-300">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                  <span>Verified authentic canonical destination. No heuristics triggered.</span>
                </div>
              )}
            </div>
          </div>

          {/* Technical Signals & Evidence */}
          {event.signals && event.signals.length > 0 && (
            <div>
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Signals & Forensic Evidence ({event.signals.length})
              </h4>
              <div className="space-y-2">
                {event.signals.map((sig) => (
                  <div
                    key={sig.id || sig.type}
                    className="rounded-lg border border-slate-200 p-3 dark:border-slate-800 dark:bg-slate-950/20"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                          {sig.category}
                        </span>
                        <span className="font-semibold text-slate-900 dark:text-slate-100">
                          {sig.title}
                        </span>
                      </div>
                      <span className="font-mono text-xs font-semibold text-rose-600 dark:text-rose-400">
                        +{sig.weight} pts
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                      {sig.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Device & Agent Metadata */}
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs dark:border-slate-800 dark:bg-slate-950">
            <div className="font-semibold text-slate-700 dark:text-slate-300">Privacy & Source Assurance</div>
            <p className="mt-1 text-slate-500 dark:text-slate-400">
              Captured via PhishGuard Extension v{event.extensionVersion} ({event.browserVersion || 'Chrome MV3'}) on{' '}
              {event.os || 'Endpoint'}. Zero credentials, keystrokes, form contents, or session tokens were recorded.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end border-t border-slate-200 px-6 py-3 dark:border-slate-800">
          <button
            onClick={onClose}
            className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
          >
            Close Event Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
