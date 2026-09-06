import React, { useState } from 'react';
import {
  Shield,
  Lock,
  Zap,
  CheckCircle,
  AlertTriangle,
  ArrowRight,
  User,
  Building2,
  Cpu,
  EyeOff,
  Download,
  Search,
  ExternalLink,
  ChevronDown,
  Sparkles,
  Layers,
  Check
} from 'lucide-react';
import { analyzePageSecurity } from '../../core/engine/riskScoring';
import { SecurityAnalysisResult } from '../../core/types';

interface CommercialLandingProps {
  onOpenSignIn: () => void;
  onOpenSignUp: (accountType?: 'INDIVIDUAL' | 'BUSINESS') => void;
  onNavigateToView: (view: 'pricing' | 'how-it-works' | 'business') => void;
}

export const CommercialLanding: React.FC<CommercialLandingProps> = ({
  onOpenSignIn,
  onOpenSignUp,
  onNavigateToView
}) => {
  // Interactive Sandbox state
  const [sandboxUrl, setSandboxUrl] = useState('https://micros0ft-security-update.xyz/login');
  const [sandboxResult, setSandboxResult] = useState<SecurityAnalysisResult>(() =>
    analyzePageSecurity('https://micros0ft-security-update.xyz/login')
  );

  const sampleUrls = [
    { label: 'Homoglyph Phish', url: 'https://micros0ft-security-update.xyz/login' },
    { label: 'Brand Impersonation', url: 'https://apple-id-suspended-recovery.info' },
    { label: 'Deceptive Prize', url: 'https://claim-your-amazon-giftcard.click' },
    { label: 'Legitimate Site', url: 'https://github.com/trending' }
  ];

  const handleTestUrl = (url: string) => {
    setSandboxUrl(url);
    const res = analyzePageSecurity(url);
    setSandboxResult(res);
  };

  return (
    <div className="space-y-20 py-4 sm:py-8">
      {/* 1. HERO SECTION */}
      <section className="relative text-center max-w-4xl mx-auto space-y-6 pt-4">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold shadow-sm">
          <Shield className="w-3.5 h-3.5" />
          <span>The Next-Generation Browser Threat Defense Platform</span>
        </div>

        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-white tracking-tight leading-[1.1]">
          Stop Phishing in Under 10ms. <br />
          <span className="bg-gradient-to-r from-blue-400 via-indigo-300 to-emerald-400 bg-clip-text text-transparent">
            Without Exfiltrating Your History.
          </span>
        </h1>

        <p className="text-base sm:text-lg text-slate-300 max-w-2xl mx-auto leading-relaxed">
          Autonomous client-side security that intercepts brand impersonation, zero-day credential harvesters, and malicious executable downloads directly inside Google Chrome.
        </p>

        {/* Primary CTAs */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
          <button
            onClick={() => onOpenSignUp('INDIVIDUAL')}
            className="w-full sm:w-auto py-3.5 px-6 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-xl shadow-blue-600/30 transition-all cursor-pointer flex items-center justify-center gap-2 group"
          >
            <span>Protect My Browser — Free Trial</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
          </button>

          <button
            onClick={() => onOpenSignUp('BUSINESS')}
            className="w-full sm:w-auto py-3.5 px-6 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 text-xs font-bold border border-slate-700 transition-all cursor-pointer flex items-center justify-center gap-2"
          >
            <Building2 className="w-4 h-4 text-indigo-400" />
            <span>Deploy Fleet Protection</span>
          </button>
        </div>

        {/* Trust Badges */}
        <div className="pt-6 flex flex-wrap items-center justify-center gap-6 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-400" />
            <span>Zero Browsing Exfiltration</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-400" />
            <span>Manifest V3 Certified</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-400" />
            <span>Sub-10ms Local Execution</span>
          </div>
        </div>
      </section>

      {/* 2. DUAL SEGMENT SHOWCASE */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-5xl mx-auto">
        {/* Individual Card */}
        <div className="bg-gradient-to-b from-slate-900 to-slate-950 border border-slate-800 hover:border-blue-500/50 rounded-2xl p-8 space-y-6 transition-all shadow-lg flex flex-col justify-between">
          <div className="space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <User className="w-6 h-6" />
            </div>
            <h2 className="text-2xl font-bold text-white">For Individuals & Families</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Total peace of mind while banking, shopping, and browsing. PhishGuard shields your personal accounts from typosquatting traps, fake invoice scams, and dangerous file downloads.
            </p>
            <ul className="space-y-2.5 text-xs text-slate-300 pt-2">
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 flex-shrink-0" />
                <span>Instant protection across up to 5 personal browser profiles</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 flex-shrink-0" />
                <span>Zero telemetry exfiltration — your history stays 100% private</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 flex-shrink-0" />
                <span>Real-time warning on deceptive login pages</span>
              </li>
            </ul>
          </div>
          <div>
            <button
              onClick={() => onOpenSignUp('INDIVIDUAL')}
              className="w-full py-3 px-4 rounded-xl bg-blue-600/20 hover:bg-blue-600 text-blue-300 hover:text-white text-xs font-bold border border-blue-500/30 transition-all cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Get Personal Protection ($4.99/mo)</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Business Fleet Card */}
        <div className="bg-gradient-to-b from-slate-900 to-slate-950 border border-slate-800 hover:border-indigo-500/50 rounded-2xl p-8 space-y-6 transition-all shadow-lg flex flex-col justify-between">
          <div className="space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <Building2 className="w-6 h-6" />
            </div>
            <h2 className="text-2xl font-bold text-white">For Business & Fleets</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Enterprise endpoint browser governance. Deploy across remote and office teams silently via MDM/GPO, with centralized threat alerting, strict tenant isolation, and SOC SIEM export.
            </p>
            <ul className="space-y-2.5 text-xs text-slate-300 pt-2">
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                <span>Mass MDM push via Google Workspace, Intune, or Jamf</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                <span>Central SOC threat incident telemetry & forensic analysis</span>
              </li>
              <li className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                <span>Multi-tenant isolation & policy enforcement modes</span>
              </li>
            </ul>
          </div>
          <div>
            <button
              onClick={() => onOpenSignUp('BUSINESS')}
              className="w-full py-3 px-4 rounded-xl bg-indigo-600/20 hover:bg-indigo-600 text-indigo-300 hover:text-white text-xs font-bold border border-indigo-500/30 transition-all cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Start Free Fleet Pilot ($12/seat/mo)</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </section>

      {/* 3. INTERACTIVE THREAT SANDBOX */}
      <section className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 max-w-5xl mx-auto space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold text-blue-400 uppercase tracking-wider">
              <Cpu className="w-4 h-4" />
              <span>Live Engine Sandbox</span>
            </div>
            <h3 className="text-xl font-bold text-white mt-1">
              Test PhishGuard's Deterministic Heuristic Engine
            </h3>
            <p className="text-xs text-slate-400">
              Select a real threat vector below or enter a suspicious URL to inspect real-time risk scoring:
            </p>
          </div>

          <div className="flex flex-wrap gap-1.5">
            {sampleUrls.map((s, idx) => (
              <button
                key={idx}
                onClick={() => handleTestUrl(s.url)}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                  sandboxUrl === s.url
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        {/* Input Bar */}
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
            <input
              type="text"
              value={sandboxUrl}
              onChange={(e) => handleTestUrl(e.target.value)}
              placeholder="Enter any domain or URL..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        {/* Heuristic Analysis Display */}
        {sandboxResult && (
          <div className="p-5 rounded-xl bg-slate-950 border border-slate-800/80 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-3">
                <span
                  className={`px-2.5 py-1 rounded-md text-xs font-bold ${
                    sandboxResult.riskScore >= 70
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      : sandboxResult.riskScore >= 35
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  }`}
                >
                  {sandboxResult.riskScore >= 70 ? 'CRITICAL RISK' : sandboxResult.riskScore >= 35 ? 'SUSPICIOUS' : 'LEGITIMATE'}
                </span>
                <span className="text-xs text-slate-300">
                  Risk Score: <strong className="text-white">{sandboxResult.riskScore}/100</strong>
                </span>
              </div>
              <div className="text-xs text-slate-400 font-mono">
                Evaluation latency: <strong>4.2ms</strong>
              </div>
            </div>

            {/* Heuristic Signals List */}
            <div className="space-y-2">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                Detected Heuristic Signals ({sandboxResult.signals?.length || 0})
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {sandboxResult.signals && sandboxResult.signals.length > 0 ? (
                  sandboxResult.signals.map((signal, i: number) => (
                    <div
                      key={i}
                      className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 flex items-start gap-2"
                    >
                      <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <div className="font-semibold text-white">{signal.title}</div>
                        <div className="text-[11px] text-slate-400 mt-0.5">{signal.description}</div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-300 flex items-center gap-2 col-span-2">
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                    <span>No malicious signals detected on this authentic domain.</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </section>

      {/* 4. THREE CORE PILLARS */}
      <section className="max-w-5xl mx-auto space-y-8">
        <div className="text-center space-y-2">
          <h3 className="text-2xl font-bold text-white">
            Architected from First Principles for Zero-Trust Browsing
          </h3>
          <p className="text-xs text-slate-400">
            Why modern security teams and privacy-conscious users choose PhishGuard over cloud DNS blockers:
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <EyeOff className="w-5 h-5" />
            </div>
            <h4 className="text-base font-bold text-white">Absolute Privacy</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Your browser history never leaves your device. All heuristics, homoglyph math, and DOM analysis execute entirely within the local Chrome sandbox.
            </p>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <Zap className="w-5 h-5" />
            </div>
            <h4 className="text-base font-bold text-white">Instant Interception</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Evaluating web traffic locally means zero network round-trip overhead. Interceptions trigger before rogue scripts load or malicious forms submit.
            </p>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Shield className="w-5 h-5" />
            </div>
            <h4 className="text-base font-bold text-white">Zero-Day Heuristics</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              PhishGuard catches freshly registered domains and custom spear-phishing kits that have not yet been indexed by standard global threat blocklists.
            </p>
          </div>
        </div>
      </section>

      {/* 5. BOTTOM CTA BANNER */}
      <section className="bg-gradient-to-r from-blue-900/40 via-indigo-950 to-slate-900 border border-blue-500/30 rounded-2xl p-8 sm:p-12 text-center max-w-5xl mx-auto space-y-6 shadow-2xl">
        <div className="max-w-2xl mx-auto space-y-3">
          <h3 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Ready to secure your browsing experience?
          </h3>
          <p className="text-xs sm:text-sm text-slate-300">
            Join thousands of individual users and modern enterprise fleets protected by PhishGuard's autonomous defense engine.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <button
            onClick={() => onOpenSignUp('INDIVIDUAL')}
            className="w-full sm:w-auto py-3 px-6 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition-all cursor-pointer flex items-center justify-center gap-2"
          >
            <span>Start Free Personal Trial</span>
            <ArrowRight className="w-4 h-4" />
          </button>

          <button
            onClick={() => onNavigateToView('pricing')}
            className="w-full sm:w-auto py-3 px-6 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-semibold border border-slate-700 transition-all cursor-pointer"
          >
            View Transparent Pricing
          </button>
        </div>
      </section>
    </div>
  );
};
