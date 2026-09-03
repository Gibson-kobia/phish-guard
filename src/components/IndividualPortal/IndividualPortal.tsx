import React, { useState, useEffect } from 'react';
import {
  Shield,
  Laptop,
  CheckCircle,
  AlertTriangle,
  Download,
  Key,
  CreditCard,
  User,
  Clock,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Lock,
  Plus
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { generateExtensionZipBlob } from '../../utils/extensionFiles';

export const IndividualPortal: React.FC = () => {
  const { user, authFetch, logout } = useAuth();

  const [overview, setOverview] = useState<any>(null);
  const [devices, setDevices] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [enrollToken, setEnrollToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [downloadingZip, setDownloadingZip] = useState(false);

  // Settings State
  const [displayName, setDisplayName] = useState(user?.name || '');
  const [newPassword, setNewPassword] = useState('');
  const [settingsSuccess, setSettingsSuccess] = useState<string | null>(null);
  const [settingsError, setSettingsError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const [ovRes, devRes, evRes] = await Promise.all([
        authFetch('/api/individual/overview'),
        authFetch('/api/individual/devices'),
        authFetch('/api/individual/events')
      ]);

      if (ovRes.ok) {
        const ovData = await ovRes.json();
        setOverview(ovData);
      }
      if (devRes.ok) {
        const devData = await devRes.json();
        setDevices(devData.devices || []);
      }
      if (evRes.ok) {
        const evData = await evRes.json();
        setEvents(evData.events || []);
      }
    } catch (err) {
      console.warn('Failed to load individual portal data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleGenerateToken = async () => {
    try {
      const res = await authFetch('/api/individual/enroll-token', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setEnrollToken(data.token?.token || data.token);
      }
    } catch (err) {
      console.error('Failed to generate token:', err);
    }
  };

  const handleDownloadZip = async () => {
    try {
      setDownloadingZip(true);
      const blob = await generateExtensionZipBlob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `phishguard-personal-${user?.id?.slice(0, 8) || 'extension'}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to download extension package:', err);
    } finally {
      setDownloadingZip(false);
    }
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setSettingsSuccess(null);
    setSettingsError(null);

    try {
      const res = await authFetch('/api/individual/profile', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: displayName,
          password: newPassword ? newPassword : undefined
        })
      });

      if (res.ok) {
        setSettingsSuccess('Profile updated successfully.');
        setNewPassword('');
      } else {
        const data = await res.json();
        setSettingsError(data.error || 'Failed to update profile.');
      }
    } catch (err: any) {
      setSettingsError(err?.message || 'Network error updating profile.');
    }
  };

  if (loading && !overview) {
    return (
      <div className="py-20 flex flex-col items-center justify-center gap-3">
        <RefreshCw className="w-6 h-6 text-blue-500 animate-spin" />
        <span className="text-xs text-slate-400">Loading your personal shield dashboard...</span>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto py-6 space-y-8">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-blue-900/40 via-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center text-blue-400 flex-shrink-0">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">Personal Shield Dashboard</h1>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                ACTIVE
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Welcome back, <strong>{user?.name}</strong> • {user?.email}
            </p>
          </div>
        </div>

        <button
          onClick={loadData}
          className="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-all cursor-pointer flex items-center gap-2"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Status</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Shield Status</span>
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-extrabold text-white flex items-center gap-2">
            <span>Protected</span>
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
          </div>
          <p className="text-[11px] text-slate-500">Autonomous local heuristic evaluation</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Protected Browsers</span>
            <Laptop className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-extrabold text-white">
            {overview?.stats?.protectedDevices || devices.length || 1} / {overview?.stats?.maxDevices || 5}
          </div>
          <p className="text-[11px] text-slate-500">Active profiles on Personal plan</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Threats Blocked</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-extrabold text-white">
            {overview?.stats?.blockedThreatsCount || events.length || 0}
          </div>
          <p className="text-[11px] text-slate-500">Harmful sites intercepted locally</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Current Plan</span>
            <CreditCard className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-extrabold text-white">Personal Shield</div>
          <p className="text-[11px] text-emerald-400 font-medium">Billed Annually ($49/yr)</p>
        </div>
      </div>

      {/* Main Grid: Devices & Installation Guide */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column (2 cols): Protected Devices & Installation */}
        <div className="lg:col-span-2 space-y-8">
          {/* Extension Installation & Token Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">Setup Your Browser Extension</h2>
                <p className="text-xs text-slate-400">
                  Install PhishGuard on Chrome, Brave, or Edge in 3 easy steps
                </p>
              </div>
              <button
                onClick={handleDownloadZip}
                disabled={downloadingZip}
                className="py-2 px-4 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-semibold shadow-md shadow-blue-600/20 transition-all cursor-pointer flex items-center gap-2"
              >
                {downloadingZip ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Download className="w-3.5 h-3.5" />
                )}
                <span>Download Extension Package</span>
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 text-xs">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                <span className="w-6 h-6 rounded-lg bg-blue-500/20 text-blue-400 font-bold flex items-center justify-center text-xs">
                  1
                </span>
                <h4 className="font-semibold text-white">Extract Archive</h4>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Download the ZIP package and extract it to any local folder on your computer.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                <span className="w-6 h-6 rounded-lg bg-blue-500/20 text-blue-400 font-bold flex items-center justify-center text-xs">
                  2
                </span>
                <h4 className="font-semibold text-white">Load Unpacked</h4>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Go to <code className="bg-slate-900 px-1 py-0.5 rounded text-blue-300">chrome://extensions</code>, enable Developer Mode, and click <strong>Load unpacked</strong>.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                <span className="w-6 h-6 rounded-lg bg-blue-500/20 text-blue-400 font-bold flex items-center justify-center text-xs">
                  3
                </span>
                <h4 className="font-semibold text-white">Activate Shield</h4>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  Pin PhishGuard to your browser toolbar. Your browser is now protected in real time!
                </p>
              </div>
            </div>

            {/* Optional Personal Enrollment Token */}
            <div className="pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
              <div className="space-y-0.5">
                <span className="font-semibold text-white">Personal Device Enrollment Key</span>
                <p className="text-[11px] text-slate-400">
                  Optional key to automatically link extension telemetry to your personal dashboard.
                </p>
              </div>

              {enrollToken ? (
                <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-xl border border-blue-500/30 font-mono text-blue-300 text-xs">
                  <Key className="w-3.5 h-3.5 text-blue-400" />
                  <span>{enrollToken}</span>
                </div>
              ) : (
                <button
                  onClick={handleGenerateToken}
                  className="py-1.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-all cursor-pointer flex items-center gap-1.5"
                >
                  <Key className="w-3.5 h-3.5" />
                  <span>Generate Key</span>
                </button>
              )}
            </div>
          </div>

          {/* Enrolled Devices List */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">Your Protected Devices</h2>
                <p className="text-xs text-slate-400">
                  {devices.length} of {overview?.stats?.maxDevices || 5} browser seats enrolled
                </p>
              </div>
            </div>

            <div className="divide-y divide-slate-800/60">
              {devices.map((dev) => (
                <div key={dev.id} className="py-3.5 flex items-center justify-between gap-4 text-xs">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                      <Laptop className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="font-semibold text-white flex items-center gap-2">
                        <span>{dev.deviceName}</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          {dev.status || 'ACTIVE'}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        {dev.browser} • Extension v{dev.extensionVersion || '1.0.0'}
                      </div>
                    </div>
                  </div>

                  <div className="text-right text-[11px] text-slate-500">
                    <div>Enrolled: {new Date(dev.enrolledAt || Date.now()).toLocaleDateString()}</div>
                    <div className="text-emerald-400 font-medium">Real-Time Protection On</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Interception Log */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div>
              <h2 className="text-base font-bold text-white">Recent Threat Interceptions</h2>
              <p className="text-xs text-slate-400">
                Log of malicious URLs and deceptive forms blocked on your devices
              </p>
            </div>

            {events.length === 0 ? (
              <div className="p-6 rounded-xl bg-slate-950 border border-slate-800/60 text-center space-y-2">
                <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto" />
                <h4 className="text-xs font-semibold text-white">Your Browsing is Clean</h4>
                <p className="text-[11px] text-slate-400 max-w-sm mx-auto">
                  No phishing attacks or deceptive form submissions have targeted your enrolled browsers recently.
                </p>
              </div>
            ) : (
              <div className="divide-y divide-slate-800/60">
                {events.slice(0, 5).map((ev) => (
                  <div key={ev.eventId || ev.id} className="py-3 flex items-center justify-between gap-4 text-xs">
                    <div className="flex items-center gap-2.5">
                      <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
                      <div>
                        <div className="font-semibold text-white font-mono">{ev.domain || ev.url}</div>
                        <div className="text-[11px] text-slate-400">{ev.category || 'Phishing Trap Intercepted'}</div>
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                      BLOCKED
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Profile & Subscription Card */}
        <div className="space-y-6">
          {/* Subscription Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                <CreditCard className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">Personal Subscription</h3>
                <p className="text-[11px] text-slate-400">Manage billing & seats</p>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-3 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Plan:</span>
                <span className="font-bold text-white">Personal Shield</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Billing:</span>
                <span className="text-white">$49.00 / year</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Device Limit:</span>
                <span className="text-white">5 Browser Profiles</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Status:</span>
                <span className="text-emerald-400 font-bold">Active (Auto-Renew)</span>
              </div>
            </div>

            <button
              onClick={() => alert('Billing portal integration ready (Stripe configured).')}
              className="w-full py-2 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-all cursor-pointer text-center"
            >
              Manage Billing & Invoices
            </button>
          </div>

          {/* Profile & Security Settings */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                <User className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">Account Settings</h3>
                <p className="text-[11px] text-slate-400">Update name & security password</p>
              </div>
            </div>

            {settingsSuccess && (
              <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs">
                {settingsSuccess}
              </div>
            )}
            {settingsError && (
              <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs">
                {settingsError}
              </div>
            )}

            <form onSubmit={handleUpdateProfile} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-medium">Display Name</label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">New Password (optional)</label>
                <input
                  type="password"
                  placeholder="Leave blank to keep current"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  minLength={8}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
                />
              </div>

              <button
                type="submit"
                className="w-full py-2 px-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md shadow-blue-600/20 transition-all cursor-pointer"
              >
                Save Changes
              </button>
            </form>

            <div className="pt-3 border-t border-slate-800/80">
              <button
                onClick={logout}
                className="w-full py-2 px-3 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 text-xs font-semibold border border-rose-500/20 transition-all cursor-pointer"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
