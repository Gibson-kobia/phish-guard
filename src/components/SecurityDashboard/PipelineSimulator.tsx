import React, { useState } from 'react';
import {
  Send,
  Radio,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Play,
  Layers,
  Cpu,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Lock,
  Globe
} from 'lucide-react';
import { SecurityIncident, Verdict, SecurityActionTaken } from '../../core/types';

interface PipelineSimulatorProps {
  onTelemetryDispatched?: () => void;
}

export const PipelineSimulator: React.FC<PipelineSimulatorProps> = ({ onTelemetryDispatched }) => {
  const [url, setUrl] = useState('https://vintedmarket.netlify.app/login/verify-account');
  const [title, setTitle] = useState('Vinted UK - Login & Account Verification');
  const [hasPassword, setHasPassword] = useState(true);
  const [hasPayment, setHasPayment] = useState(false);
  const [hasOtp, setHasOtp] = useState(true);
  const [detectedBrand, setDetectedBrand] = useState('Vinted');
  
  const [isLoading, setIsLoading] = useState(false);
  const [lastResult, setLastResult] = useState<any>(null);
  const [lastIncident, setLastIncident] = useState<SecurityIncident | null>(null);

  // Quick Preset Scenarios
  const scenarios = [
    {
      id: 'vinted-netlify',
      label: 'Vinted Phish (Netlify + Login)',
      desc: 'Third-party hosting + Brand impersonation + Credential form',
      url: 'https://vintedmarket.netlify.app/login/verify-account',
      title: 'Vinted UK - Login & Verification',
      password: true,
      payment: false,
      otp: true,
      brand: 'Vinted',
      expected: 'DANGEROUS (Score 100) -> BLOCKED'
    },
    {
      id: 'portfolio-vercel',
      label: 'Dev Portfolio (Vercel Safe)',
      desc: 'Third-party hosting ONLY, no login, no brand mismatch',
      url: 'https://alex-developer-portfolio.vercel.app/projects',
      title: 'Alex Rivera - Full Stack Engineer Portfolio',
      password: false,
      payment: false,
      otp: false,
      brand: '',
      expected: 'SAFE (Score 0) -> ALLOWED'
    },
    {
      id: 'paypal-vercel',
      label: 'PayPal Phish (Vercel + Auth)',
      desc: 'Vercel + PayPal login form',
      url: 'https://paypal-security-center.vercel.app/signin',
      title: 'PayPal: Log in to your account',
      password: true,
      payment: true,
      otp: false,
      brand: 'PayPal',
      expected: 'DANGEROUS (Score 100) -> BLOCKED'
    },
    {
      id: 'bare-ip',
      label: 'Bare IP Credential Harvester',
      desc: 'Direct IPv4 hosting + password form',
      url: 'http://192.168.1.105:8080/bank/login',
      title: 'Online Banking Portal Login',
      password: true,
      payment: false,
      otp: false,
      brand: '',
      expected: 'DANGEROUS (Score 100) -> BLOCKED'
    },
    {
      id: 'official-jumia',
      label: 'Official Jumia Store',
      desc: 'Official canonical domain + legitimate auth',
      url: 'https://www.jumia.com.ng/customer/account/login',
      title: 'Jumia Nigeria - Official Store Login',
      password: true,
      payment: false,
      otp: false,
      brand: 'Jumia',
      expected: 'SAFE (Score 0-2) -> ALLOWED'
    }
  ];

  const applyScenario = (sc: typeof scenarios[0]) => {
    setUrl(sc.url);
    setTitle(sc.title);
    setHasPassword(sc.password);
    setHasPayment(sc.payment);
    setHasOtp(sc.otp);
    setDetectedBrand(sc.brand);
  };

  const dispatchObservationEvent = async () => {
    setIsLoading(true);
    try {
      const payload = {
        event_type: 'page_analysis',
        url,
        title,
        forms: {
          password: hasPassword,
          payment: hasPayment,
          otp: hasOtp
        },
        detected_brands: detectedBrand ? [detectedBrand] : [],
        timestamp: new Date().toISOString()
      };

      const res = await fetch('/api/telemetry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      setLastResult(data);

      if (data.incidentId) {
        // Fetch generated incident
        try {
          const incRes = await fetch(`/api/incidents/${data.incidentId}`);
          if (incRes.ok) {
            const incData = await incRes.json();
            setLastIncident(incData.incident);
          }
        } catch {
          // Ignore
        }
      } else {
        setLastIncident(null);
      }

      if (onTelemetryDispatched) {
        onTelemetryDispatched();
      }
    } catch (err: any) {
      console.error('Failed to dispatch telemetry event:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-indigo-400 text-xs font-semibold uppercase tracking-wider">
              <Radio className="w-4 h-4" />
              <span>Real-Time Extension Observation Simulator</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Test & Verify Telemetry Pipeline (Extension → VPS Backend)
            </h2>
            <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
              Dispatches real privacy-preserving observation payloads to the backend compound correlation engine (<code className="text-blue-300">POST /api/telemetry</code>) and checks calculated risk, signals, MITRE ATT&CK techniques, and generated incidents.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20 text-xs font-semibold">
              <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse"></span>
              Live Pipeline Active
            </span>
          </div>
        </div>
      </div>

      {/* Preset Scenario Selector */}
      <div className="space-y-2">
        <label className="text-xs font-bold uppercase tracking-wider text-slate-400">
          Quick Test Scenarios (1-Click Pipeline Verification)
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
          {scenarios.map((sc) => {
            const isSelected = url === sc.url;
            return (
              <button
                key={sc.id}
                onClick={() => applyScenario(sc)}
                className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                  isSelected
                    ? 'bg-blue-950/60 border-blue-500/50 shadow-md shadow-blue-950/50'
                    : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/60'
                }`}
              >
                <div>
                  <div className="text-xs font-bold text-white line-clamp-1">{sc.label}</div>
                  <div className="text-[11px] text-slate-400 mt-1 line-clamp-2">{sc.desc}</div>
                </div>
                <div className="mt-3 pt-2 border-t border-slate-800/60 text-[10px] font-semibold text-amber-300">
                  {sc.expected}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Observation Payload Form */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-blue-400" />
            Simulated Browser Observation State
          </h3>
          <span className="text-xs text-slate-500">Zero secrets collected</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Target Page URL</label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/page"
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Page Document Title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Vinted UK - Login"
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 pt-2">
          <label className="flex items-center gap-2.5 bg-slate-950 border border-slate-800/80 p-2.5 rounded-xl cursor-pointer hover:border-slate-700">
            <input
              type="checkbox"
              checked={hasPassword}
              onChange={(e) => setHasPassword(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0"
            />
            <span className="text-xs text-slate-300 font-medium">Password Field Present</span>
          </label>

          <label className="flex items-center gap-2.5 bg-slate-950 border border-slate-800/80 p-2.5 rounded-xl cursor-pointer hover:border-slate-700">
            <input
              type="checkbox"
              checked={hasPayment}
              onChange={(e) => setHasPayment(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0"
            />
            <span className="text-xs text-slate-300 font-medium">Payment / Card Input</span>
          </label>

          <label className="flex items-center gap-2.5 bg-slate-950 border border-slate-800/80 p-2.5 rounded-xl cursor-pointer hover:border-slate-700">
            <input
              type="checkbox"
              checked={hasOtp}
              onChange={(e) => setHasOtp(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0"
            />
            <span className="text-xs text-slate-300 font-medium">2FA / OTP Code Input</span>
          </label>

          <div className="flex items-center gap-2 bg-slate-950 border border-slate-800/80 px-2.5 py-1.5 rounded-xl">
            <span className="text-xs text-slate-400 shrink-0 font-medium">Brand:</span>
            <input
              type="text"
              value={detectedBrand}
              onChange={(e) => setDetectedBrand(e.target.value)}
              placeholder="e.g. Vinted"
              className="bg-transparent border-0 text-xs text-white focus:outline-none w-full"
            />
          </div>
        </div>

        <div className="pt-2 flex justify-end">
          <button
            onClick={dispatchObservationEvent}
            disabled={isLoading || !url}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white shadow-lg shadow-blue-600/30 transition cursor-pointer"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Processing Relational Correlation...</span>
              </>
            ) : (
              <>
                <Send className="w-4 h-4" />
                <span>Dispatch Observation Event to Server Pipeline</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Live Server Response & Incident Card */}
      {lastResult && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Live Server Correlation Response
            </h3>
            <span className="text-xs font-mono text-slate-400">Endpoint: POST /api/telemetry</span>
          </div>

          {/* Forensic Incident Result Card (Exact formatting requested) */}
          {lastResult.incidentId ? (
            <div className="bg-slate-900 border border-red-500/40 rounded-2xl p-6 relative overflow-hidden shadow-xl shadow-red-950/20">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="px-3 py-1 rounded-lg bg-red-500/20 border border-red-500/30 text-red-400 text-xs font-mono font-bold">
                    {lastResult.incidentId}
                  </div>
                  <div className="px-3 py-1 rounded-lg bg-red-500 text-white text-xs font-extrabold uppercase tracking-wider">
                    {lastResult.verdict} ({lastResult.score}/100)
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400 font-semibold">Action Enforced:</span>
                  <span className="px-3 py-1 rounded-lg bg-red-600 text-white text-xs font-bold">
                    {lastResult.action}
                  </span>
                </div>
              </div>

              <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-3">
                  <div>
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Target Domain & URL</span>
                    <div className="text-sm font-mono font-semibold text-white mt-0.5 break-all">
                      {url}
                    </div>
                  </div>

                  <div>
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Signals & Evidence Verified</span>
                    <div className="mt-2 space-y-1.5">
                      {lastResult.signals && lastResult.signals.map((sig: any, idx: number) => (
                        <div key={idx} className="flex items-start gap-2 text-xs text-slate-200">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                          <span>{sig.title}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <div>
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">MITRE ATT&CK® Techniques</span>
                    <div className="flex flex-wrap gap-1.5 mt-1.5">
                      {lastResult.mitreTechniques && lastResult.mitreTechniques.map((code: string) => (
                        <span key={code} className="px-2 py-0.5 rounded-md bg-purple-500/10 text-purple-300 border border-purple-500/20 text-xs font-mono font-semibold">
                          {code}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Relational Factor Summary</span>
                    <p className="text-xs text-slate-300 bg-slate-950 p-3 rounded-xl border border-slate-800 mt-1 font-mono leading-relaxed">
                      {lastResult.explanation?.relationshipSummary || 'Compound factors triggered.'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-emerald-500/30 rounded-2xl p-5 flex items-start gap-4">
              <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-0.5 rounded-md bg-emerald-500/20 text-emerald-300 text-xs font-bold">
                    {lastResult.verdict} (Score {lastResult.score}/100)
                  </span>
                  <span className="text-xs text-slate-400">Action: <strong className="text-white">{lastResult.action}</strong></span>
                </div>
                <h4 className="text-sm font-semibold text-white">Baseline Safe Behavior Verified</h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  The page contains no brand impersonation, no deceptive login forms, and clean hosting patterns. False positive prevented successfully.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
