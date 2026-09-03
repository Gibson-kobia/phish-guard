import React, { useState } from 'react';
import { Shield, Check, Building2, User, Zap, Lock, ArrowRight, HelpCircle } from 'lucide-react';

interface PricingViewProps {
  onSelectPlan: (plan: 'personal' | 'business' | 'enterprise') => void;
}

export const PricingView: React.FC<PricingViewProps> = ({ onSelectPlan }) => {
  const [billingCycle, setBillingCycle] = useState<'monthly' | 'annual'>('annual');

  return (
    <div className="max-w-6xl mx-auto py-8 space-y-12">
      {/* Header */}
      <div className="text-center space-y-4 max-w-2xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold">
          <Shield className="w-3.5 h-3.5" />
          <span>Transparent Commercial Licensing</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Simple, Predictable Protection for Everyone
        </h1>
        <p className="text-sm text-slate-400">
          Whether safeguarding your personal browser or securing an entire corporate fleet, PhishGuard delivers sub-10ms deterministic threat interception with zero browsing data exfiltration.
        </p>

        {/* Billing Switcher */}
        <div className="pt-4 flex items-center justify-center gap-3 text-xs">
          <span className={billingCycle === 'monthly' ? 'text-white font-semibold' : 'text-slate-400'}>
            Monthly Billing
          </span>
          <button
            type="button"
            onClick={() => setBillingCycle(billingCycle === 'monthly' ? 'annual' : 'monthly')}
            className="w-12 h-6 rounded-full bg-slate-800 p-1 relative transition-colors focus:outline-none cursor-pointer"
          >
            <div
              className={`w-4 h-4 rounded-full bg-blue-500 transition-transform ${
                billingCycle === 'annual' ? 'translate-x-6' : 'translate-x-0'
              }`}
            />
          </button>
          <div className="flex items-center gap-1.5">
            <span className={billingCycle === 'annual' ? 'text-white font-semibold' : 'text-slate-400'}>
              Annual Billing
            </span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              Save 20%
            </span>
          </div>
        </div>
      </div>

      {/* Pricing Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-stretch">
        {/* Tier 1: Personal Protection */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-7 flex flex-col justify-between relative hover:border-slate-700 transition-all">
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                <User className="w-5 h-5" />
              </div>
              <span className="text-[11px] font-bold px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                Individual & Family
              </span>
            </div>

            <div>
              <h3 className="text-xl font-bold text-white">Personal Shield</h3>
              <p className="text-xs text-slate-400 mt-1">
                For individuals seeking privacy-first protection against phishing, brand spoofing, and malicious downloads.
              </p>
            </div>

            <div className="flex items-baseline gap-1.5">
              <span className="text-4xl font-extrabold text-white">
                {billingCycle === 'annual' ? '$49' : '$4.99'}
              </span>
              <span className="text-xs text-slate-400">
                {billingCycle === 'annual' ? '/ year' : '/ month'}
              </span>
            </div>

            <div className="pt-4 border-t border-slate-800/80 space-y-3 text-xs text-slate-300">
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 flex-shrink-0" />
                <span>Up to <strong>5 personal browser profiles</strong></span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 flex-shrink-0" />
                <span>Zero browsing history transmission</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 flex-shrink-0" />
                <span>Real-time brand spoof & homoglyph block</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 flex-shrink-0" />
                <span>Malicious executable download intercept</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-blue-400 flex-shrink-0" />
                <span>Chrome Manifest V3 lightweight engine</span>
              </div>
            </div>
          </div>

          <div className="pt-8">
            <button
              onClick={() => onSelectPlan('personal')}
              className="w-full py-3 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold border border-slate-700 transition-all cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Get Personal Shield</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tier 2: Business Pro (Popular) */}
        <div className="bg-gradient-to-b from-blue-950/40 via-slate-900 to-slate-900 border-2 border-blue-500/50 rounded-2xl p-7 flex flex-col justify-between relative shadow-xl shadow-blue-500/10">
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-blue-600 text-white text-[10px] font-bold tracking-wider uppercase shadow-md">
            Most Popular
          </div>

          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
                <Building2 className="w-5 h-5" />
              </div>
              <span className="text-[11px] font-bold px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Growing Teams
              </span>
            </div>

            <div>
              <h3 className="text-xl font-bold text-white">Business Fleet</h3>
              <p className="text-xs text-slate-400 mt-1">
                Centralized visibility and policy enforcement for modern teams and distributed workforces.
              </p>
            </div>

            <div className="flex items-baseline gap-1.5">
              <span className="text-4xl font-extrabold text-white">
                {billingCycle === 'annual' ? '$10' : '$12'}
              </span>
              <span className="text-xs text-slate-400">
                / seat / month (billed {billingCycle})
              </span>
            </div>

            <div className="pt-4 border-t border-slate-800/80 space-y-3 text-xs text-slate-300">
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>Everything in Personal, plus:</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>Centralized SOC Incident Dashboard</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>Fleet Enrollment Tokens & Mass Push</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>Strict Tenant Isolation & Policy Control</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>Automated CSV / SIEM Log Export</span>
              </div>
            </div>
          </div>

          <div className="pt-8">
            <button
              onClick={() => onSelectPlan('business')}
              className="w-full py-3 px-4 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-lg shadow-blue-600/30 transition-all cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Start 14-Day Free Fleet Trial</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tier 3: Enterprise */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-7 flex flex-col justify-between relative hover:border-slate-700 transition-all">
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                <Lock className="w-5 h-5" />
              </div>
              <span className="text-[11px] font-bold px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                Enterprise SOC
              </span>
            </div>

            <div>
              <h3 className="text-xl font-bold text-white">Enterprise Shield</h3>
              <p className="text-xs text-slate-400 mt-1">
                For organizations with custom compliance, dedicated hosting, or high-scale MDM automation requirements.
              </p>
            </div>

            <div className="flex items-baseline gap-1.5">
              <span className="text-3xl font-extrabold text-white">Custom</span>
              <span className="text-xs text-slate-400">volume discounts</span>
            </div>

            <div className="pt-4 border-t border-slate-800/80 space-y-3 text-xs text-slate-300">
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                <span>Unlimited enterprise endpoints</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                <span>MDM GPO / Jamf / Intune silent deployment</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                <span>SAML 2.0 / Okta / Azure AD SSO</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                <span>Dedicated SecOps Technical Account Manager</span>
              </div>
              <div className="flex items-center gap-2.5">
                <Check className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                <span>Custom Threat Allowlist & Heuristic Tuning</span>
              </div>
            </div>
          </div>

          <div className="pt-8">
            <button
              onClick={() => onSelectPlan('enterprise')}
              className="w-full py-3 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold border border-slate-700 transition-all cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Contact Enterprise Sales</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Payment & Security Assurance */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-400">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-emerald-400 flex-shrink-0" />
          <span>
            <strong>Secure Billing Guarantee:</strong> Commercial payments are processed through PCI-DSS Level 1 infrastructure (Stripe integration ready). Cancel anytime from your account dashboard.
          </span>
        </div>
      </div>
    </div>
  );
};
