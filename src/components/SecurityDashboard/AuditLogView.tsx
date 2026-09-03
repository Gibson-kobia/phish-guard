import React, { useState, useEffect } from 'react';
import { Shield, Clock, User, FileText, CheckCircle2, RefreshCw } from 'lucide-react';
import { AuditLogEntry } from '../../core/types';

export const AuditLogView: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = () => {
    setLoading(true);
    fetch('/api/audit')
      .then((res) => res.json())
      .then((data) => {
        setLogs(data.logs || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white p-4 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <div>
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
            Administrative Audit Log
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Immutable log of policy modifications, device enrollments, and version governance
          </p>
        </div>
        <button
          onClick={fetchLogs}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh Log
        </button>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-slate-200 bg-slate-50/80 font-semibold text-slate-600 dark:border-slate-800 dark:bg-slate-950/60 dark:text-slate-400">
            <tr>
              <th className="px-4 py-3">Timestamp</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Target</th>
              <th className="px-4 py-3">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
            {logs.map((item) => (
              <tr key={item.id} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/30">
                <td className="whitespace-nowrap px-4 py-3 font-mono text-slate-500 dark:text-slate-400">
                  {new Date(item.timestamp).toLocaleString()}
                </td>
                <td className="px-4 py-3 font-semibold text-slate-800 dark:text-slate-200">
                  {item.actor}
                </td>
                <td className="px-4 py-3">
                  <span className="rounded bg-slate-100 px-2 py-0.5 font-mono text-[10px] font-bold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                    {item.action}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-slate-600 dark:text-slate-400">
                  {item.target}
                </td>
                <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                  {item.details}
                </td>
              </tr>
            ))}

            {logs.length === 0 && (
              <tr>
                <td colSpan={5} className="py-8 text-center text-xs text-slate-500 dark:text-slate-400">
                  No audit log entries recorded.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
