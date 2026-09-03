import React from 'react';
import { Shield, Lock, Cpu, EyeOff, Zap, CheckCircle, ArrowRight, Layers, Database } from 'lucide-react';

export const HowItWorksView: React.FC<{ onGetStarted: () => void }> = ({ onGetStarted }) => {
  return (
    <div className="max-w-5xl mx-auto py-8 space-y-16">
      {/* Header */}
      <div className="text-center space-y-4 max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold">
          <Cpu className="w-3.5 h-3.5" />
          <span>Under the Hood Architecture</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Deterministic Threat Defense. Zero Exfiltration.
        </h1>
        <p className="text-sm text-slate-400 leading-relaxed">
          Traditional security tools proxy every URL you visit through a remote cloud server, creating latency and compromising user privacy. PhishGuard brings the threat intelligence and analysis engine directly inside your browser.
        </p>
      </div>

      {/* Step by Step Pipeline */}
      <div className="space-y-8">
        <h2 className="text-xl font-bold text-white text-center">
          How Every Page Navigation is Evaluated in Under 10ms
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Step 1 */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 relative">
            <div className="w-10 h-10 rounded-xl bg-blue-500/20 text-blue-400 font-bold flex items-center justify-center text-sm border border-blue-500/30">
              01
            </div>
            <h3 className="text-base font-bold text-white">Pre-Navigation Intercept</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Using Chrome Manifest V3 Service Workers, PhishGuard checks the target URL before network sockets connect, analyzing high-entropy paths, known deceptive TLDs, and homoglyph mutations.
            </p>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800/80 text-[11px] text-slate-400 font-mono">
              micros0ft-login[.]xyz → Impersonation Score: 96%
            </div>
          </div>

          {/* Step 2 */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 relative">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/20 text-indigo-400 font-bold flex items-center justify-center text-sm border border-indigo-500/30">
              02
            </div>
            <h3 className="text-base font-bold text-white">DOM Heuristic Correlation</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Content scripts immediately evaluate form action destinations, password input fields on non-authentic origins, fake SSL badges, and psychological coercion triggers (e.g. fake countdown timers).
            </p>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800/80 text-[11px] text-slate-400 font-mono">
              Password form on unverified domain → BLOCKED
            </div>
          </div>

          {/* Step 3 */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 relative">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/20 text-emerald-400 font-bold flex items-center justify-center text-sm border border-emerald-500/30">
              03
            </div>
            <h3 className="text-base font-bold text-white">Sub-10ms Action & Warning</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              If risk exceeds safe thresholds, PhishGuard immediately redirects the tab to an offline cryptographic block page, terminating session cookies and preventing payload delivery.
            </p>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800/80 text-[11px] text-slate-400 font-mono">
              Interception latency: 4.8ms | Exfiltration: 0 bytes
            </div>
          </div>
        </div>
      </div>

      {/* Comparison Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 space-y-6">
        <h2 className="text-xl font-bold text-white text-center">
          PhishGuard vs. Legacy Cloud Proxy Solutions
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-3 px-4">Evaluation Vector</th>
                <th className="py-3 px-4 text-blue-400 font-bold">PhishGuard Engine</th>
                <th className="py-3 px-4 text-slate-500">Legacy Cloud DNS/Proxy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-3.5 px-4 font-semibold text-white">User Privacy & Data Exfiltration</td>
                <td className="py-3.5 px-4 text-emerald-400 flex items-center gap-1.5 font-medium">
                  <EyeOff className="w-3.5 h-3.5" /> 100% Client-Side, Zero URLs Sent
                </td>
                <td className="py-3.5 px-4 text-slate-400">All URLs logged to remote cloud</td>
              </tr>
              <tr>
                <td className="py-3.5 px-4 font-semibold text-white">Interception Latency</td>
                <td className="py-3.5 px-4 text-emerald-400 flex items-center gap-1.5 font-medium">
                  <Zap className="w-3.5 h-3.5" /> &lt; 10ms (Instant Local Evaluation)
                </td>
                <td className="py-3.5 px-4 text-slate-400">150ms - 400ms round-trip delay</td>
              </tr>
              <tr>
                <td className="py-3.5 px-4 font-semibold text-white">Zero-Day Domain Phishing</td>
                <td className="py-3.5 px-4 text-emerald-400 flex items-center gap-1.5 font-medium">
                  <CheckCircle className="w-3.5 h-3.5" /> Deterministic Heuristics & DOM analysis
                </td>
                <td className="py-3.5 px-4 text-slate-400">Fails if domain not on blocklist yet</td>
              </tr>
              <tr>
                <td className="py-3.5 px-4 font-semibold text-white">Executable Download Protection</td>
                <td className="py-3.5 px-4 text-emerald-400 flex items-center gap-1.5 font-medium">
                  <CheckCircle className="w-3.5 h-3.5" /> Correlates origin risk with .exe/.msi payload
                </td>
                <td className="py-3.5 px-4 text-slate-400">Requires separate endpoint agent</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* CTA Box */}
      <div className="bg-gradient-to-r from-blue-900/40 via-indigo-900/40 to-slate-900 border border-blue-500/30 rounded-2xl p-8 text-center space-y-4">
        <h3 className="text-xl font-bold text-white">
          Experience True Zero-Knowledge Threat Protection
        </h3>
        <p className="text-xs text-slate-300 max-w-xl mx-auto">
          Deploy PhishGuard across your personal devices or roll it out to your company's fleet in minutes.
        </p>
        <button
          onClick={onGetStarted}
          className="py-3 px-6 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/30 transition-all cursor-pointer inline-flex items-center gap-2"
        >
          <span>Get Started Now</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
