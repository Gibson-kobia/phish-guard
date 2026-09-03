import React, { useState, useEffect, useMemo } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Info, Clock, 
  Layers, Globe, FileCode, ChevronRight, Zap, Terminal, Download,
  MessageSquareWarning, History
} from 'lucide-react';
import { analyzePageSecurity } from '../core/engine/riskScoring';
import { securityLogger } from '../core/logging/securityLogger';
import { 
  SecurityAnalysisResult, 
  FormAnalysisMetadata, 
  RedirectAnalysisData, 
  SocialEngineeringMetadata,
  DownloadSecurityContext,
  ExtensionSettings 
} from '../core/types';

const PRESET_SCENARIOS = [
  {
    name: 'PayPal Homoglyph (paypa1.com)',
    url: 'https://paypa1.com/auth/login',
    hasPassword: true,
    hasCC: false,
    isCrossOrigin: false,
    hasSocialUrgency: false,
    isDownload: false,
    category: 'Typosquatting'
  },
  {
    name: 'Netflix Billing on .xyz',
    url: 'https://netf1ix-billing-update.xyz/login/verify',
    hasPassword: true,
    hasCC: true,
    isCrossOrigin: false,
    hasSocialUrgency: true,
    isDownload: false,
    category: 'Combosquatting'
  },
  {
    name: 'Chase Online Banking Spoof',
    url: 'https://chase-online-banking-portal-secure.click/account/verify',
    hasPassword: true,
    hasCC: false,
    isCrossOrigin: false,
    hasSocialUrgency: false,
    isDownload: false,
    category: 'Lure Keywords'
  },
  {
    name: 'Raw IP Credential Login',
    url: 'http://185.220.101.5/login.php',
    hasPassword: true,
    hasCC: false,
    isInsecureHttp: true,
    isCrossOrigin: false,
    hasSocialUrgency: false,
    isDownload: false,
    category: 'IP Address'
  },
  {
    name: 'Cross-Origin Data Exfiltration',
    url: 'https://corporate-employee-portal.org/login',
    hasPassword: true,
    hasCC: false,
    isCrossOrigin: true,
    action: 'https://malicious-drop-collector.cc/api/v1/harvest',
    hasSocialUrgency: false,
    isDownload: false,
    category: 'DOM Hijack'
  },
  {
    name: 'Fake Tech Support Scare Screen',
    url: 'https://windows-defender-security-alert-call.top/help',
    hasPassword: false,
    hasCC: false,
    isCrossOrigin: false,
    hasTechSupport: true,
    isDownload: false,
    category: 'Social Engineering'
  },
  {
    name: 'Executable Download from Untrusted Host',
    url: 'https://micros0ft-office-update.xyz/download',
    hasPassword: false,
    hasCC: false,
    isCrossOrigin: false,
    hasSocialUrgency: false,
    isDownload: true,
    downloadFile: 'OfficeSetup.msi',
    category: 'Download Security'
  },
  {
    name: 'Legitimate Google Account (Safe)',
    url: 'https://accounts.google.com/signin/v2/identifier',
    hasPassword: true,
    hasCC: false,
    isCrossOrigin: false,
    hasSocialUrgency: false,
    isDownload: false,
    category: 'Legitimate'
  },
  {
    name: 'Legitimate PayPal Sign-in (Safe)',
    url: 'https://www.paypal.com/signin',
    hasPassword: true,
    hasCC: false,
    isCrossOrigin: false,
    hasSocialUrgency: false,
    isDownload: false,
    category: 'Legitimate'
  }
];

interface UrlInspectorProps {
  settings: ExtensionSettings;
  setSettings: React.Dispatch<React.SetStateAction<ExtensionSettings>>;
  onOpenPreviewTab?: () => void;
  initialUrl?: string;
}

export const UrlInspector: React.FC<UrlInspectorProps> = ({ settings, initialUrl }) => {
  const [urlInput, setUrlInput] = useState(initialUrl || 'https://paypa1.com/auth/login');

  useEffect(() => {
    if (initialUrl) {
      setUrlInput(initialUrl);
    }
  }, [initialUrl]);
  const [hasPassword, setHasPassword] = useState(true);
  const [hasCreditCard, setHasCreditCard] = useState(false);
  const [hasSsn, setHasSsn] = useState(false);
  const [has2Fa, setHas2Fa] = useState(false);
  const [isCrossOrigin, setIsCrossOrigin] = useState(false);
  const [formAction, setFormAction] = useState('');
  const [isInsecureHttp, setIsInsecureHttp] = useState(false);
  
  // Social engineering cues
  const [hasUrgency, setHasUrgency] = useState(false);
  const [hasTechSupportAlert, setHasTechSupportAlert] = useState(false);
  const [hasPrizeClaim, setHasPrizeClaim] = useState(false);

  // Download context
  const [isDownloadActive, setIsDownloadActive] = useState(false);
  const [downloadFilename, setDownloadFilename] = useState('OfficeSetup.msi');

  // Redirect simulator
  const [isRedirectChain, setIsRedirectChain] = useState(false);
  const [redirectHops, setRedirectHops] = useState(3);
  
  const [analysis, setAnalysis] = useState<SecurityAnalysisResult | null>(null);
  const [activeTab, setActiveTab] = useState<'signals' | 'timeline' | 'features'>('signals');
  const [activeSignalFilter, setActiveSignalFilter] = useState<'all' | 'critical' | 'dom' | 'url' | 'soceng'>('all');

  // Trigger evaluation
  useEffect(() => {
    let isMounted = true;
    
    const formMeta: FormAnalysisMetadata = {
      hasPasswordInput: hasPassword,
      hasCreditCardInput: hasCreditCard,
      hasSsnInput: hasSsn,
      hasEmailOrUserInput: true,
      has2FAInput: has2Fa,
      formsCount: (hasPassword || hasCreditCard) ? 1 : 0,
      suspiciousForms: (hasPassword || hasCreditCard) ? [{
        action: formAction || urlInput,
        method: 'POST',
        isCrossOrigin,
        isInsecureHttp,
        hasPasswordField: hasPassword,
        inputCount: 3,
        hiddenInputsCount: 1
      }] : [],
      hasHiddenCredentialFields: false
    };

    const redirectMeta: RedirectAnalysisData | undefined = isRedirectChain ? {
      initialUrl: 'https://bit.ly/3xSecurityUpdate',
      finalUrl: urlInput,
      hopCount: redirectHops,
      hops: [
        { url: 'https://bit.ly/3xSecurityUpdate', timestamp: 1 },
        { url: 'https://traffic-router-node.net/gate', timestamp: 2 },
        { url: urlInput, timestamp: 3 }
      ],
      hasCrossDomainRedirect: true,
      hasUrlShortener: true
    } : undefined;

    const phrases: string[] = [];
    if (hasUrgency) phrases.push('Account suspension / restriction notice', 'Urgent compliance deadline');
    if (hasTechSupportAlert) phrases.push('Impersonated system security alert', 'Fake toll-free tech support prompt');
    if (hasPrizeClaim) phrases.push('Reward / lottery winner lure');

    const socialMeta: SocialEngineeringMetadata | undefined = (hasUrgency || hasTechSupportAlert || hasPrizeClaim) ? {
      hasUrgencyLanguage: hasUrgency,
      hasAccountSuspensionNotice: hasUrgency,
      hasCredentialVerificationPrompt: hasUrgency,
      hasFakeTechSupportLanguage: hasTechSupportAlert,
      hasPaymentUrgency: false,
      hasPrizeOrRewardClaim: hasPrizeClaim,
      detectedPhrases: phrases,
      visibleHeadingsSample: phrases
    } : undefined;

    const downloadContext: DownloadSecurityContext | undefined = isDownloadActive ? {
      downloadId: 99,
      url: `${urlInput}/${downloadFilename}`,
      filename: downloadFilename,
      fileExtension: downloadFilename.split('.').pop() || '',
      originUrl: urlInput,
      originRiskScore: 75,
      originVerdict: 'HIGH_RISK',
      isDangerousOrigin: true,
      isExecutable: true,
      timestamp: Date.now()
    } : undefined;

    const res = analyzePageSecurity(
      urlInput,
      formMeta,
      redirectMeta,
      settings,
      socialMeta,
      downloadContext
    );

    if (isMounted) {
      setAnalysis(res);
      // Automatically record privacy-preserving security telemetry
      securityLogger.recordTelemetry(res, {
        wasFormBlocked: formMeta.hasPasswordInput && res.score >= 60
      });
    }

    return () => { isMounted = false; };
  }, [
    urlInput, hasPassword, hasCreditCard, hasSsn, has2Fa, 
    isCrossOrigin, formAction, isInsecureHttp, hasUrgency, hasTechSupportAlert,
    hasPrizeClaim, isDownloadActive, downloadFilename, isRedirectChain, redirectHops, settings
  ]);

  const loadPreset = (preset: typeof PRESET_SCENARIOS[0]) => {
    setUrlInput(preset.url);
    setHasPassword(preset.hasPassword);
    setHasCreditCard(preset.hasCC);
    setIsCrossOrigin(preset.isCrossOrigin);
    setFormAction(preset.action || '');
    setIsInsecureHttp(preset.isInsecureHttp || false);
    setHasUrgency(preset.hasSocialUrgency || false);
    setHasTechSupportAlert(preset.hasTechSupport || false);
    setIsDownloadActive(preset.isDownload || false);
    if (preset.downloadFile) setDownloadFilename(preset.downloadFile);
  };

  const getVerdictStyle = (verdict?: string) => {
    switch (verdict) {
      case 'DANGEROUS':
        return {
          badge: 'bg-red-600 text-white border-red-500 font-bold',
          card: 'border-red-600/60 bg-gradient-to-b from-red-950/40 to-slate-900',
          text: 'text-red-400',
          icon: <ShieldAlert className="w-5 h-5 text-red-400" />
        };
      case 'HIGH_RISK':
        return {
          badge: 'bg-red-500/20 text-red-300 border-red-500/40 font-bold',
          card: 'border-red-900/50 bg-gradient-to-b from-red-950/30 to-slate-900',
          text: 'text-red-400',
          icon: <ShieldAlert className="w-5 h-5 text-red-400" />
        };
      case 'SUSPICIOUS':
        return {
          badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40 font-bold',
          card: 'border-amber-900/50 bg-gradient-to-b from-amber-950/30 to-slate-900',
          text: 'text-amber-400',
          icon: <AlertTriangle className="w-5 h-5 text-amber-400" />
        };
      case 'LOW_RISK':
        return {
          badge: 'bg-blue-500/20 text-blue-300 border-blue-500/40 font-bold',
          card: 'border-blue-900/50 bg-gradient-to-b from-blue-950/30 to-slate-900',
          text: 'text-blue-400',
          icon: <Info className="w-5 h-5 text-blue-400" />
        };
      default:
        return {
          badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-bold',
          card: 'border-emerald-900/50 bg-gradient-to-b from-emerald-950/30 to-slate-900',
          text: 'text-emerald-400',
          icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />
        };
    }
  };

  const verdictStyle = getVerdictStyle(analysis?.verdict);

  const filteredSignals = useMemo(() => {
    if (!analysis) return [];
    if (activeSignalFilter === 'critical') return analysis.signals.filter(s => s.severity === 'CRITICAL' || s.severity === 'HIGH');
    if (activeSignalFilter === 'dom') return analysis.signals.filter(s => s.category === 'DOM_SECURITY');
    if (activeSignalFilter === 'url') return analysis.signals.filter(s => s.category === 'URL_STRUCTURE' || s.category === 'TYPOSQUATTING');
    if (activeSignalFilter === 'soceng') return analysis.signals.filter(s => s.category === 'SOCIAL_ENGINEERING' || s.category === 'DOWNLOAD_SECURITY');
    return analysis.signals;
  }, [analysis, activeSignalFilter]);

  return (
    <div className="space-y-6">
      {/* Top Threat Scenarios Ribbon */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Security Test Scenarios
            </span>
          </div>
          <span className="text-xs text-slate-400">Click any preset to load into the evaluation pipeline</span>
        </div>
        <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-thin">
          {PRESET_SCENARIOS.map((preset, idx) => (
            <button
              key={idx}
              onClick={() => loadPreset(preset)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border text-left whitespace-nowrap transition-all flex items-center gap-2 cursor-pointer ${
                urlInput === preset.url
                  ? 'bg-blue-600/20 border-blue-500/50 text-blue-300 shadow-sm'
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700 hover:text-white'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${
                preset.category === 'Legitimate' ? 'bg-emerald-400' : 'bg-red-400'
              }`} />
              <span>{preset.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid: Input Simulators vs Evaluation Engine Output */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Interactive Feature Simulators */}
        <div className="lg:col-span-6 space-y-5">
          {/* Target URL Input */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-400" />
                <span>Target Webpage URL</span>
              </label>
              <span className="text-[11px] text-slate-400 font-mono">100% Local On-Device Scan</span>
            </div>

            <input
              id="input-target-url"
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://example.com/login"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-100 font-mono focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>

          {/* Form & DOM Security Simulator */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  DOM &amp; Form Fields
                </span>
              </div>
              <span className="text-[11px] text-emerald-400 font-medium">Privacy Safe</span>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={hasPassword}
                  onChange={(e) => setHasPassword(e.target.checked)}
                  className="rounded accent-blue-500"
                />
                <span className="text-slate-300 font-medium">Password Field</span>
              </label>

              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={hasCreditCard}
                  onChange={(e) => setHasCreditCard(e.target.checked)}
                  className="rounded accent-blue-500"
                />
                <span className="text-slate-300 font-medium">Credit Card / CVV</span>
              </label>

              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={hasSsn}
                  onChange={(e) => setHasSsn(e.target.checked)}
                  className="rounded accent-blue-500"
                />
                <span className="text-slate-300 font-medium">SSN / Tax ID</span>
              </label>

              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={has2Fa}
                  onChange={(e) => setHas2Fa(e.target.checked)}
                  className="rounded accent-blue-500"
                />
                <span className="text-slate-300 font-medium">2FA OTP Token</span>
              </label>

              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer hover:border-slate-700 col-span-2">
                <input
                  type="checkbox"
                  checked={isCrossOrigin}
                  onChange={(e) => setIsCrossOrigin(e.target.checked)}
                  className="rounded accent-blue-500"
                />
                <div>
                  <span className="text-slate-300 font-medium block">Cross-Origin Form Action</span>
                  <span className="text-[11px] text-slate-400">Target action posts credentials to a separate third-party domain</span>
                </div>
              </label>
            </div>

            {isCrossOrigin && (
              <div className="pt-1">
                <label className="text-[11px] text-slate-400 mb-1 block">Cross-Origin Drop Target</label>
                <input
                  type="text"
                  value={formAction}
                  onChange={(e) => setFormAction(e.target.value)}
                  placeholder="https://malicious-drop-collector.cc/api/v1/harvest"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                />
              </div>
            )}
          </div>

          {/* Social Engineering Cues Simulator */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <MessageSquareWarning className="w-4 h-4 text-amber-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Social Engineering &amp; Coercive Cues
                </span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={hasUrgency}
                  onChange={(e) => setHasUrgency(e.target.checked)}
                  className="rounded accent-amber-500"
                />
                <span className="text-slate-300 font-medium">Account Suspension Threat</span>
              </label>

              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={hasTechSupportAlert}
                  onChange={(e) => setHasTechSupportAlert(e.target.checked)}
                  className="rounded accent-amber-500"
                />
                <span className="text-slate-300 font-medium">Fake Tech Support Alert</span>
              </label>
            </div>
          </div>

          {/* Download Context & Redirect Chain Simulator */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <Download className="w-4 h-4 text-purple-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Download Context &amp; Redirect Evasion
                </span>
              </div>
            </div>

            <div className="space-y-3 text-xs">
              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={isDownloadActive}
                  onChange={(e) => setIsDownloadActive(e.target.checked)}
                  className="rounded accent-purple-500"
                />
                <div className="flex-1">
                  <span className="text-slate-300 font-medium block">Simulate Active File Download</span>
                  <span className="text-[11px] text-slate-400">Correlates executable download (.exe/.msi) with origin risk level</span>
                </div>
              </label>

              <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 cursor-pointer hover:border-slate-700">
                <input
                  type="checkbox"
                  checked={isRedirectChain}
                  onChange={(e) => setIsRedirectChain(e.target.checked)}
                  className="rounded accent-purple-500"
                />
                <div className="flex-1">
                  <span className="text-slate-300 font-medium block">Simulate Multi-Hop Shortener Redirect</span>
                  <span className="text-[11px] text-slate-400">Tests evasive link trampoline hops (bit.ly → intermediary → target)</span>
                </div>
              </label>
            </div>
          </div>
        </div>

        {/* Right Column: Security Analysis & Timeline Output */}
        <div className="lg:col-span-6 space-y-5">
          {/* Main Risk Status Card */}
          <div className={`border rounded-xl p-6 transition-all ${verdictStyle.card}`}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2.5">
                {verdictStyle.icon}
                <span className={`text-xs font-bold uppercase tracking-wider px-2.5 py-1 rounded-md border ${verdictStyle.badge}`}>
                  {analysis?.verdict.replace('_', ' ') || 'EVALUATING'}
                </span>
                {analysis?.targetBrand && (
                  <span className="text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-600/50 px-2 py-0.5 rounded">
                    Mimics {analysis.targetBrand.name}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                <span>{analysis?.scanDurationMs || 0}ms Latency</span>
              </div>
            </div>

            {/* Score Display Bar */}
            <div className="space-y-2 mb-5">
              <div className="flex items-baseline justify-between">
                <div>
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Risk Assessment Index</span>
                  <p className="text-[11px] text-slate-400">Multi-signal deterministic heuristic score</p>
                </div>
                <div className="flex items-baseline gap-1">
                  <span className={`text-3xl font-extrabold font-mono ${verdictStyle.text}`}>
                    {analysis?.score || 0}
                  </span>
                  <span className="text-slate-400 text-xs font-mono">/ 100</span>
                </div>
              </div>

              {/* Meter bar */}
              <div className="w-full h-2.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                <div
                  className={`h-full transition-all duration-300 rounded-full ${
                    (analysis?.score || 0) >= 90 ? 'bg-red-600' :
                    (analysis?.score || 0) >= 70 ? 'bg-red-500' :
                    (analysis?.score || 0) >= 40 ? 'bg-amber-500' :
                    (analysis?.score || 0) >= 20 ? 'bg-blue-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.min(100, Math.max(4, analysis?.score || 0))}%` }}
                />
              </div>
            </div>

            {/* Assessment Explanations */}
            <div className="space-y-2 border-t border-slate-800/80 pt-4">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                Primary Assessment Reasons
              </span>
              <div className="space-y-1.5">
                {analysis?.reasons.map((reason, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-xs text-slate-200">
                    <ChevronRight className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Tabbed View: Signals vs Timeline vs Features */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex gap-2">
                <button
                  onClick={() => setActiveTab('signals')}
                  className={`px-3 py-1 rounded-lg text-xs font-bold cursor-pointer transition-colors ${
                    activeTab === 'signals'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-200 bg-slate-950'
                  }`}
                >
                  Signals ({analysis?.signals.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab('timeline')}
                  className={`px-3 py-1 rounded-lg text-xs font-bold cursor-pointer transition-colors flex items-center gap-1.5 ${
                    activeTab === 'timeline'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-200 bg-slate-950'
                  }`}
                >
                  <History className="w-3.5 h-3.5" />
                  <span>Timeline ({analysis?.timeline.length || 0})</span>
                </button>
              </div>

              {activeTab === 'signals' && (
                <div className="flex gap-1 text-[11px]">
                  <button
                    onClick={() => setActiveSignalFilter('all')}
                    className={`px-2 py-0.5 rounded cursor-pointer ${activeSignalFilter === 'all' ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-white'}`}
                  >
                    All
                  </button>
                  <button
                    onClick={() => setActiveSignalFilter('critical')}
                    className={`px-2 py-0.5 rounded cursor-pointer ${activeSignalFilter === 'critical' ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-white'}`}
                  >
                    High/Crit
                  </button>
                </div>
              )}
            </div>

            {/* TAB 1: SIGNALS LIST */}
            {activeTab === 'signals' && (
              <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
                {filteredSignals.length === 0 ? (
                  <div className="p-4 text-center text-xs text-slate-400 bg-slate-950 rounded-lg border border-slate-800">
                    No active threat signals triggered in this category.
                  </div>
                ) : (
                  filteredSignals.map((signal, idx) => (
                    <div
                      key={idx}
                      className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2 hover:border-slate-700 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase ${
                            signal.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                            signal.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                            signal.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border-amber-500/30' :
                            'bg-blue-500/20 text-blue-400 border-blue-500/30'
                          }`}>
                            {signal.severity}
                          </span>
                          <span className="text-xs font-bold text-slate-200">{signal.title}</span>
                        </div>
                        <span className="text-[11px] font-mono text-slate-400">+{signal.weight} pts</span>
                      </div>

                      <p className="text-xs text-slate-400 leading-relaxed">
                        {signal.description}
                      </p>

                      {signal.evidence && Object.keys(signal.evidence).length > 0 && (
                        <div className="bg-slate-900/90 rounded p-2 text-[11px] font-mono text-slate-300 space-y-1">
                          {Object.entries(signal.evidence).map(([k, v]) => (
                            <div key={k} className="flex justify-between">
                              <span className="text-slate-400">{k}:</span>
                              <span className="text-blue-300 font-semibold">{String(v)}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}

            {/* TAB 2: TIMELINE LIST */}
            {activeTab === 'timeline' && (
              <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
                {analysis?.timeline.map((ev, idx) => (
                  <div key={idx} className="flex gap-3 p-2.5 bg-slate-950 rounded-lg border border-slate-800">
                    <div className={`w-2.5 h-2.5 rounded-full mt-1.5 shrink-0 ${
                      ev.severity === 'CRITICAL' ? 'bg-red-500 shadow-sm shadow-red-500' :
                      ev.severity === 'HIGH' ? 'bg-orange-500' :
                      ev.severity === 'MEDIUM' ? 'bg-amber-500' :
                      ev.severity === 'LOW' ? 'bg-blue-500' : 'bg-emerald-500'
                    }`} />
                    <div className="flex-1 space-y-0.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-slate-200">{ev.title}</span>
                        <span className="text-[10px] font-mono text-slate-500">{ev.timeString || '00:00:00'}</span>
                      </div>
                      <p className="text-[11px] text-slate-400">{ev.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
