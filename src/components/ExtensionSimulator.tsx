import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Settings, RefreshCw, 
  ArrowLeft, ExternalLink, Globe, Lock, Shield, Eye
} from 'lucide-react';
import { analyzePageSecurity } from '../engine/riskScoring';
import { AnalysisResult } from '../types';

export const ExtensionSimulator: React.FC = () => {
  const [activeScreen, setActiveScreen] = useState<'popup' | 'warning' | 'banner'>('popup');
  const [mockUrl, setMockUrl] = useState('https://paypa1.com/auth/login');
  const [mockScore, setMockScore] = useState(88);
  const [mockVerdict, setMockVerdict] = useState<'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK'>('HIGH_RISK');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [bannerDismissed, setBannerDismissed] = useState(false);

  const mockSignals = [
    {
      title: 'Homoglyph Lookalike Detected',
      severity: 'CRITICAL',
      desc: 'Hostname "paypa1.com" uses homoglyph "1" to imitate protected canonical brand "paypal.com".'
    },
    {
      title: 'Credential Harvesting Target',
      severity: 'HIGH',
      desc: 'Page requests unauthenticated password submission on an untrusted lookalike host.'
    },
    {
      title: 'Compound Phishing Signature',
      severity: 'CRITICAL',
      desc: 'Multi-factor concurrence: homoglyph typosquatting combined with credential form.'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Simulator Switcher Ribbon */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Eye className="w-4 h-4 text-blue-400" />
            <span>Chrome Extension Visual Preview Simulator</span>
          </h2>
          <p className="text-xs text-slate-400">
            Interactive preview of how PhishGuard renders inside Google Chrome&apos;s UI layers.
          </p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={() => setActiveScreen('popup')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors ${
              activeScreen === 'popup'
                ? 'bg-blue-600 text-white'
                : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            Popup UI
          </button>
          <button
            onClick={() => setActiveScreen('warning')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors ${
              activeScreen === 'warning'
                ? 'bg-blue-600 text-white'
                : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            Warning Interstitial
          </button>
          <button
            onClick={() => { setActiveScreen('banner'); setBannerDismissed(false); }}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors ${
              activeScreen === 'banner'
                ? 'bg-blue-600 text-white'
                : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            In-Page Banner
          </button>
        </div>
      </div>

      {/* Simulator Canvas */}
      <div className="flex justify-center p-6 bg-slate-950 rounded-2xl border border-slate-800/80 min-h-[480px] items-center">
        {/* POPUP VIEW */}
        {activeScreen === 'popup' && (
          <div className="w-[360px] bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden text-slate-100 font-sans">
            {/* Mock Chrome Extension Popup Header */}
            <div className="p-3.5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-blue-400" />
                <div>
                  <div className="font-bold text-xs leading-none">PhishGuard</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">Real-Time Security</div>
                </div>
              </div>
              <div className="flex gap-1.5">
                <button className="w-7 h-7 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400 hover:text-white">
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
                <button className="w-7 h-7 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400 hover:text-white">
                  <Settings className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Status Card */}
            <div className="p-3.5 space-y-3">
              <div className="p-3 rounded-lg border border-red-800/60 bg-gradient-to-b from-red-950/40 to-slate-900 space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-red-500 text-red-950">
                    HIGH RISK
                  </span>
                  <div className="flex items-baseline gap-1">
                    <span className="text-[10px] text-slate-400">RISK</span>
                    <span className="text-lg font-black font-mono text-red-400">88</span>
                    <span className="text-[10px] text-slate-500">/100</span>
                  </div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 block uppercase font-mono">Active Domain</span>
                  <span className="text-xs font-mono font-bold text-white break-all">paypa1.com</span>
                </div>
              </div>

              {/* Assessment Summary */}
              <div className="space-y-1.5">
                <span className="text-[10px] font-bold uppercase text-slate-400 tracking-wider">Assessment Summary</span>
                <ul className="space-y-1 text-xs">
                  <li className="bg-slate-800/80 p-2 rounded border-l-2 border-red-500 text-slate-200">
                    Homoglyph lookalike for &quot;paypal.com&quot; detected
                  </li>
                  <li className="bg-slate-800/80 p-2 rounded border-l-2 border-red-500 text-slate-200">
                    Password collection requested on suspicious lookalike
                  </li>
                </ul>
              </div>

              {/* Signals Container */}
              <div className="space-y-1.5">
                <span className="text-[10px] font-bold uppercase text-slate-400 tracking-wider">Detected Signals (3)</span>
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {mockSignals.map((sig, idx) => (
                    <div key={idx} className="p-2 bg-slate-800/60 rounded border border-slate-800 space-y-1">
                      <div className="flex justify-between items-center">
                        <span className="text-[11px] font-bold text-slate-200">{sig.title}</span>
                        <span className="text-[9px] font-bold px-1.5 rounded bg-red-500/20 text-red-400">
                          {sig.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 leading-tight">{sig.desc}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Footer */}
              <div className="pt-2 border-t border-slate-800 flex justify-between text-[10px] text-slate-500">
                <span>🔒 Zero credential logging</span>
                <span className="text-blue-400">Advanced Rules</span>
              </div>
            </div>
          </div>
        )}

        {/* WARNING INTERSTITIAL VIEW */}
        {activeScreen === 'warning' && (
          <div className="w-full max-w-xl bg-slate-900 border border-red-900/60 border-t-4 border-t-red-600 rounded-xl p-6 shadow-2xl space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-slate-400 tracking-wider">🛡️ PHISHGUARD DEFENSE</span>
              <span className="text-xs font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                HIGH RISK
              </span>
            </div>

            <div>
              <h2 className="text-lg font-bold text-white">Potentially Dangerous Website Detected</h2>
              <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                PhishGuard intercepted your navigation because this website displays multiple behavioral signals commonly associated with phishing, credential harvesting, or deceptive brand impersonation.
              </p>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-slate-400">Destination URL:</span>
                <span className="text-red-400 font-bold">{mockUrl}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Calculated Risk:</span>
                <span className="text-red-400 font-bold">{mockScore} / 100</span>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-xs font-bold uppercase text-slate-400">Detection Signals &amp; Evidence</span>
              <div className="space-y-1.5">
                {mockSignals.map((s, idx) => (
                  <div key={idx} className="p-2.5 bg-slate-950 rounded border-l-2 border-red-500 space-y-0.5">
                    <div className="flex justify-between text-xs">
                      <span className="font-bold text-slate-200">{s.title}</span>
                      <span className="text-[10px] text-red-400 font-bold">{s.severity}</span>
                    </div>
                    <p className="text-[11px] text-slate-400">{s.desc}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <button className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold flex items-center gap-2 cursor-pointer">
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Return to Safety</span>
              </button>
              <button
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium cursor-pointer"
              >
                {showAdvanced ? 'Hide Advanced' : 'Advanced Details'}
              </button>
            </div>

            {showAdvanced && (
              <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-2 text-xs">
                <p className="text-amber-400">
                  ⚠️ Submitting passwords or payment data on this page poses a severe risk of credential theft.
                </p>
                <div className="flex gap-2">
                  <button className="px-2.5 py-1 rounded bg-transparent border border-red-900 text-red-400 hover:bg-red-950/40 text-[11px] font-bold cursor-pointer">
                    Proceed Anyway (Not Recommended)
                  </button>
                  <button className="px-2.5 py-1 rounded bg-transparent border border-slate-700 text-slate-300 hover:bg-slate-800 text-[11px] cursor-pointer">
                    Add Domain to Allowlist
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* IN-PAGE BANNER VIEW */}
        {activeScreen === 'banner' && (
          <div className="w-full max-w-2xl space-y-4">
            {!bannerDismissed ? (
              <div className="bg-slate-900 border border-slate-700 border-b-2 border-b-red-500 rounded-lg p-3 flex items-center justify-between text-xs text-white shadow-xl">
                <div className="flex items-center gap-2.5">
                  <span className="text-base">⚠️</span>
                  <span>
                    <strong>PhishGuard Warning:</strong> This site shows indicators commonly associated with phishing (Risk Score: <strong>88/100</strong>). Do not submit credentials.
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-white text-[11px] font-semibold hover:bg-slate-700 cursor-pointer">
                    View Details
                  </button>
                  <button
                    onClick={() => setBannerDismissed(true)}
                    className="text-slate-400 hover:text-white px-1.5 py-0.5 text-sm cursor-pointer"
                  >
                    ✕
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-center p-4 bg-slate-900/50 rounded-lg border border-slate-800 text-xs text-slate-400">
                Banner dismissed. <button onClick={() => setBannerDismissed(false)} className="text-blue-400 underline ml-1 cursor-pointer">Reset Banner</button>
              </div>
            )}

            {/* Mock website page beneath */}
            <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-8 text-center space-y-3">
              <div className="w-12 h-12 bg-slate-800 rounded-full mx-auto flex items-center justify-center text-slate-500">
                <Globe className="w-6 h-6" />
              </div>
              <h3 className="text-sm font-bold text-slate-300">Simulated Third-Party Webpage</h3>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                PhishGuard content script executes in the background at <code>document_idle</code>, inspecting form tags while respecting user privacy.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
