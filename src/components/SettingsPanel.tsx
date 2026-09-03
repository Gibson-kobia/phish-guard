import React, { useState } from 'react';
import { 
  Sliders, Shield, Plus, X, RotateCcw, 
  Check, Lock, AlertCircle, Building2
} from 'lucide-react';
import { ExtensionSettings } from '../types';
import { DEFAULT_SETTINGS } from '../config/rules';
import { DEFAULT_PROTECTED_BRANDS } from '../config/brands';

interface SettingsPanelProps {
  settings: ExtensionSettings;
  setSettings: React.Dispatch<React.SetStateAction<ExtensionSettings>>;
}

export const SettingsPanel: React.FC<SettingsPanelProps> = ({ settings, setSettings }) => {
  const [newAllowDomain, setNewAllowDomain] = useState('');
  const [newBlockDomain, setNewBlockDomain] = useState('');
  const [brandSearch, setBrandSearch] = useState('');

  const handleAddAllow = () => {
    const val = newAllowDomain.trim().toLowerCase();
    if (val && !settings.allowlist.includes(val)) {
      setSettings(prev => ({
        ...prev,
        allowlist: [...prev.allowlist, val]
      }));
      setNewAllowDomain('');
    }
  };

  const handleRemoveAllow = (domain: string) => {
    setSettings(prev => ({
      ...prev,
      allowlist: prev.allowlist.filter(d => d !== domain)
    }));
  };

  const handleAddBlock = () => {
    const val = newBlockDomain.trim().toLowerCase();
    if (val && !settings.blocklist.includes(val)) {
      setSettings(prev => ({
        ...prev,
        blocklist: [...prev.blocklist, val]
      }));
      setNewBlockDomain('');
    }
  };

  const handleRemoveBlock = (domain: string) => {
    setSettings(prev => ({
      ...prev,
      blocklist: prev.blocklist.filter(d => d !== domain)
    }));
  };

  const handleReset = () => {
    if (confirm('Reset detection engine configurations to default values?')) {
      setSettings(DEFAULT_SETTINGS);
    }
  };

  const filteredBrands = DEFAULT_PROTECTED_BRANDS.filter(b => 
    b.name.toLowerCase().includes(brandSearch.toLowerCase()) ||
    b.canonicalDomains.some(d => d.includes(brandSearch.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Sliders className="w-5 h-5 text-blue-400" />
            <h2 className="text-base font-bold text-white">Detection Engine Parameters &amp; Brand Watchlist</h2>
          </div>
          <p className="text-xs text-slate-400">
            Tune heuristic sensitivity thresholds, inspect protected canonical brands, and manage localized allow/block rules.
          </p>
        </div>

        <button
          onClick={handleReset}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset Defaults</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column: Sensitivity & Weights */}
        <div className="space-y-6">
          {/* Sensitivity Profile */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block">
              Detection Sensitivity Profile
            </span>

            <div className="grid grid-cols-3 gap-2.5">
              {[
                { id: 'CONSERVATIVE', label: 'Conservative', desc: 'Minimal alerts' },
                { id: 'BALANCED', label: 'Balanced', desc: 'Standard baseline' },
                { id: 'AGGRESSIVE', label: 'Aggressive', desc: 'Strict checks' }
              ].map(profile => (
                <button
                  key={profile.id}
                  onClick={() => setSettings(prev => ({ ...prev, detectionSensitivity: profile.id as any }))}
                  className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                    settings.detectionSensitivity === profile.id
                      ? 'bg-blue-600/20 border-blue-500/50 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <span className="text-xs font-bold block text-slate-200">{profile.label}</span>
                  <span className="text-[10px] text-slate-400">{profile.desc}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Threshold Sliders */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block">
              Risk Score Thresholds
            </span>

            <div className="space-y-4 text-xs">
              <div>
                <div className="flex justify-between font-mono mb-1.5">
                  <span className="text-slate-300">Warning Banner Threshold:</span>
                  <span className="text-amber-400 font-bold">{settings.warningThreshold} pts</span>
                </div>
                <input
                  type="range"
                  min="30"
                  max="80"
                  value={settings.warningThreshold}
                  onChange={(e) => setSettings(prev => ({ ...prev, warningThreshold: parseInt(e.target.value, 10) }))}
                  className="w-full accent-amber-500"
                />
              </div>

              <div>
                <div className="flex justify-between font-mono mb-1.5">
                  <span className="text-slate-300">Blocking Interstitial Threshold:</span>
                  <span className="text-red-400 font-bold">{settings.blockThreshold} pts</span>
                </div>
                <input
                  type="range"
                  min="60"
                  max="95"
                  value={settings.blockThreshold}
                  onChange={(e) => setSettings(prev => ({ ...prev, blockThreshold: parseInt(e.target.value, 10) }))}
                  className="w-full accent-red-500"
                />
              </div>
            </div>
          </div>

          {/* Toggles */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block">
              Active Heuristic Sub-Engines
            </span>

            <div className="space-y-2.5 text-xs">
              {[
                { key: 'enableUrlAnalysis', label: 'URL Structure & Entropy Analyzer' },
                { key: 'enableTyposquatting', label: 'Typosquatting & Homoglyph Engine' },
                { key: 'enableDomAnalysis', label: 'DOM Form & Credential Inspector' },
                { key: 'enableRedirectAnalysis', label: 'Multi-Hop Redirect Chain Tracker' },
                { key: 'enableReputationLayer', label: 'Local Threat Reputation Database' }
              ].map(({ key, label }) => (
                <label key={key} className="flex items-center justify-between p-2 rounded-lg bg-slate-950 border border-slate-800 cursor-pointer">
                  <span className="text-slate-300">{label}</span>
                  <input
                    type="checkbox"
                    checked={(settings as any)[key]}
                    onChange={(e) => setSettings(prev => ({ ...prev, [key]: e.target.checked }))}
                    className="accent-blue-500 rounded"
                  />
                </label>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Protected Brands Watchlist & Custom Lists */}
        <div className="space-y-6">
          {/* Protected Brands Watchlist */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                <Building2 className="w-4 h-4 text-blue-400" />
                <span>Protected Brand Watchlist ({DEFAULT_PROTECTED_BRANDS.length})</span>
              </span>
              <input
                type="text"
                value={brandSearch}
                onChange={(e) => setBrandSearch(e.target.value)}
                placeholder="Search brands..."
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto pr-1">
              {filteredBrands.map(b => (
                <div key={b.id} className="p-2 bg-slate-950 rounded border border-slate-800 text-xs">
                  <span className="font-bold text-slate-200 block">{b.name}</span>
                  <span className="text-[10px] text-slate-400 font-mono truncate block">
                    {b.canonicalDomains.join(', ')}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Allowlist & Blocklist */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block">
              Trusted Allowlist
            </span>
            <div className="flex gap-2">
              <input
                type="text"
                value={newAllowDomain}
                onChange={(e) => setNewAllowDomain(e.target.value)}
                placeholder="e.g. corporate-intranet.internal"
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={handleAddAllow}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold cursor-pointer"
              >
                Add
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
              {settings.allowlist.map(d => (
                <span key={d} className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-xs text-emerald-300 font-mono">
                  <span>{d}</span>
                  <button onClick={() => handleRemoveAllow(d)} className="text-slate-400 hover:text-red-400 cursor-pointer">×</button>
                </span>
              ))}
            </div>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block">
              Custom Threat Blocklist
            </span>
            <div className="flex gap-2">
              <input
                type="text"
                value={newBlockDomain}
                onChange={(e) => setNewBlockDomain(e.target.value)}
                placeholder="e.g. custom-phish-domain.xyz"
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={handleAddBlock}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold cursor-pointer"
              >
                Add
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
              {settings.blocklist.map(d => (
                <span key={d} className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-xs text-red-300 font-mono">
                  <span>{d}</span>
                  <button onClick={() => handleRemoveBlock(d)} className="text-slate-400 hover:text-red-400 cursor-pointer">×</button>
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
