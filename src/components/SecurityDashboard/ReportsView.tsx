import React, { useState, useEffect } from 'react';
import {
  Download,
  Calendar,
  ShieldCheck,
  ShieldAlert,
  Layers,
  FileSpreadsheet,
  TrendingUp,
  BarChart3
} from 'lucide-react';

interface ReportsViewProps {
  onExportCsv: () => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ onExportCsv }) => {
  const [reportData, setReportData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/reports')
      .then((res) => res.json())
      .then((data) => {
        setReportData(data);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, []);

  return (
    <div className="space-y-6">
      {/* Report Summary Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <div>
          <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
            Security Threat & Compliance Report
          </h3>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Aggregated metrics across all registered endpoints in your organization
          </p>
        </div>

        <button
          onClick={onExportCsv}
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white shadow-xs hover:bg-blue-700"
        >
          <FileSpreadsheet className="h-4 w-4" />
          Export All Events (.CSV)
        </button>
      </div>

      {/* 7-Day Activity Trend */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">
              7-Day Detection Breakdown
            </h4>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Daily counts of blocked threats, warnings, and benign navigations
            </p>
          </div>
          <div className="flex items-center gap-3 text-xs">
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-rose-500" /> Blocked
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-500" /> Warned
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" /> Safe
            </span>
          </div>
        </div>

        <div className="space-y-3">
          {(reportData?.dailyBreakdown || []).map((day: any) => {
            const total = Math.max(1, day.total);
            const blockedPct = (day.blocked / total) * 100;
            const warnedPct = (day.warned / total) * 100;
            const safePct = (day.safe / total) * 100;

            return (
              <div key={day.date} className="space-y-1">
                <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
                  <span className="font-mono font-medium">{day.date}</span>
                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                    {day.total} total ({day.blocked} blocked)
                  </span>
                </div>
                <div className="flex h-3 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                  {day.blocked > 0 && (
                    <div
                      style={{ width: `${blockedPct}%` }}
                      className="bg-rose-500 transition-all"
                    />
                  )}
                  {day.warned > 0 && (
                    <div
                      style={{ width: `${warnedPct}%` }}
                      className="bg-amber-500 transition-all"
                    />
                  )}
                  {day.safe > 0 && (
                    <div
                      style={{ width: `${safePct}%` }}
                      className="bg-emerald-500 transition-all"
                    />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Target Breakdown Grid */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {/* Top Targeted Brands */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">
            Impersonation Targets
          </h4>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Most frequent brands spoofed in phishing campaigns
          </p>

          <div className="mt-4 space-y-3">
            {(reportData?.topTargetedBrands || []).map((item: any) => (
              <div key={item.brand} className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-800 dark:text-slate-200">
                  {item.brand}
                </span>
                <span className="rounded-full bg-slate-100 px-2.5 py-0.5 font-mono text-xs font-bold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  {item.count} detections
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Threat Vectors */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs dark:border-slate-800 dark:bg-slate-900">
          <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">
            Threat Vectors by Category
          </h4>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Categorization based on heuristic triggers
          </p>

          <div className="mt-4 space-y-3">
            {(reportData?.topThreatCategories || []).map((cat: any) => (
              <div key={cat.category} className="flex items-center justify-between text-xs">
                <span className="text-slate-700 dark:text-slate-300">{cat.category}</span>
                <span className="font-mono text-xs font-bold text-slate-900 dark:text-slate-100">
                  {cat.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
