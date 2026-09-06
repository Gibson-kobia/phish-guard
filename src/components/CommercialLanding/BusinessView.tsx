import React from 'react';
import { Building2, Shield, Users, Server, FileText, CheckCircle2, ArrowRight, Laptop, Key, BellRing } from 'lucide-react';

export const BusinessView: React.FC<{ onStartFleetTrial: () => void }> = ({ onStartFleetTrial }) => {
  return (
    <div className="max-w-5xl mx-auto py-8 space-y-16">
      {/* Hero */}
      <div className="text-center space-y-4 max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-semibold">
          <Building2 className="w-3.5 h-3.5" />
          <span>Enterprise Fleet Threat Protection</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Modern Browser Governance & Threat Interception for Fleets
        </h1>
        <p className="text-sm text-slate-400 leading-relaxed">
          Arm your remote and in-office employees with autonomous browser security. Block spear-phishing, credential theft, and dangerous downloads before they compromise your corporate perimeter.
        </p>
        <div className="pt-2">
          <button
            onClick={onStartFleetTrial}
            className="py-3 px-6 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-lg shadow-blue-600/30 transition-all cursor-pointer inline-flex items-center gap-2"
          >
            <span>Start 14-Day Free Fleet Trial</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Fleet Features Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-7 space-y-4">
          <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Laptop className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-white">Silent MDM & GPO Deployment</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Distribute PhishGuard across thousands of macOS and Windows devices using Google Workspace Admin Console, Microsoft Intune, Jamf Pro, or Group Policy. Zero user intervention required.
          </p>
          <ul className="space-y-2 text-xs text-slate-300">
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
              <span>Pre-configured enrollment tokens</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
              <span>Locked configuration prevents employee uninstallation</span>
            </li>
          </ul>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-7 space-y-4">
          <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
            <BellRing className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-white">Centralized SOC Telemetry</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Receive real-time security alerts when threats are blocked on employee devices. High-fidelity incident logs without logging private employee web surfing history.
          </p>
          <ul className="space-y-2 text-xs text-slate-300">
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
              <span>Full threat vector & payload forensic details</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
              <span>One-click CSV & SIEM webhook forwarding</span>
            </li>
          </ul>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-7 space-y-4">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Key className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-white">Strict Tenant Isolation & RBAC</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Each company operates in a dedicated, tenant-isolated data boundary. Grant Org Admin or Read-Only Security Analyst permissions with granular role-based controls.
          </p>
          <ul className="space-y-2 text-xs text-slate-300">
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>Zero cross-tenant data leakage</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>Audit logs for all policy modifications</span>
            </li>
          </ul>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-7 space-y-4">
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <Server className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-white">Autonomous Enforcement Modes</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Tailor protection per department or across the fleet. Switch seamlessly between Full Block mode, Interactive Warn mode, or Silent Audit mode for testing.
          </p>
          <ul className="space-y-2 text-xs text-slate-300">
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-purple-400" />
              <span>Instant policy propagation to active endpoints</span>
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-purple-400" />
              <span>Offline caching for traveling & remote employees</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};
