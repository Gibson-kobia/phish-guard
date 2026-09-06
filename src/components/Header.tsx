import React from 'react';
import { Shield, Download, User, LogIn, Sparkles, Building2, Laptop, Lock, ArrowRight, RefreshCw } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { generateExtensionZipBlob } from '../utils/extensionFiles';

export type CommercialView = 'landing' | 'pricing' | 'how-it-works' | 'business' | 'portal';

interface HeaderProps {
  currentView: CommercialView;
  setCurrentView: (view: CommercialView) => void;
  onOpenSignIn: () => void;
  onOpenSignUp: (accountType?: 'INDIVIDUAL' | 'BUSINESS') => void;
  isSuperAdminRoute?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  currentView,
  setCurrentView,
  onOpenSignIn,
  onOpenSignUp,
  isSuperAdminRoute = false
}) => {
  const { user, isSuperAdmin, logout } = useAuth();
  const [downloading, setDownloading] = React.useState(false);

  const handleDownloadZip = async () => {
    try {
      setDownloading(true);
      const blob = await generateExtensionZipBlob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'phishguard-extension-v3.zip';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to generate extension zip:', err);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Brand identity */}
        <button
          onClick={() => setCurrentView('landing')}
          className="flex items-center gap-3 text-left cursor-pointer focus:outline-none"
        >
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 via-indigo-600 to-emerald-500 p-[1px] flex items-center justify-center shadow-lg shadow-blue-500/10 flex-shrink-0">
            <div className="w-full h-full bg-slate-950 rounded-xl flex items-center justify-center">
              <Shield className="w-5 h-5 text-blue-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-base tracking-tight text-white">PhishGuard</span>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Security
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">
              Zero-Exfiltration Threat Defense
            </p>
          </div>
        </button>

        {/* Commercial Navigation */}
        <nav className="hidden md:flex items-center gap-1 text-xs">
          <button
            onClick={() => setCurrentView('landing')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              currentView === 'landing'
                ? 'text-white bg-slate-800/80 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            Overview
          </button>

          <button
            onClick={() => setCurrentView('how-it-works')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              currentView === 'how-it-works'
                ? 'text-white bg-slate-800/80 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            How It Works
          </button>

          <button
            onClick={() => setCurrentView('business')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              currentView === 'business'
                ? 'text-white bg-slate-800/80 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            Business Fleet
          </button>

          <button
            onClick={() => setCurrentView('pricing')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
              currentView === 'pricing'
                ? 'text-white bg-slate-800/80 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            Pricing
          </button>
        </nav>

        {/* Right Side Actions */}
        <div className="flex items-center gap-3 text-xs">
          {/* Extension Download Shortcut */}
          <button
            onClick={handleDownloadZip}
            disabled={downloading}
            className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors cursor-pointer text-xs font-medium"
          >
            {downloading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Download className="w-3.5 h-3.5 text-blue-400" />
            )}
            <span>Get Extension (.zip)</span>
          </button>

          {/* User Account / Sign In State */}
          {user ? (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentView('portal')}
                className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 transition-all cursor-pointer"
              >
                <div className="w-6 h-6 rounded-lg bg-blue-500/20 text-blue-400 flex items-center justify-center font-bold text-[10px]">
                  {user.name.slice(0, 1).toUpperCase()}
                </div>
                <div className="text-left hidden sm:block">
                  <div className="font-semibold text-white leading-tight flex items-center gap-1.5">
                    <span>{user.name}</span>
                    <span
                      className={`text-[9px] uppercase font-bold px-1.5 py-0.2 rounded ${
                        user.role === 'SUPER_ADMIN'
                          ? 'bg-indigo-500/20 text-indigo-300'
                          : user.role === 'INDIVIDUAL'
                          ? 'bg-purple-500/20 text-purple-300'
                          : 'bg-blue-500/20 text-blue-300'
                      }`}
                    >
                      {user.role === 'INDIVIDUAL' ? 'Personal' : user.role === 'SUPER_ADMIN' ? 'SecOps' : 'Fleet Admin'}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500">
                    {user.role === 'INDIVIDUAL'
                      ? 'Personal Shield'
                      : user.organizationName || 'Fleet Portal'}
                  </div>
                </div>
              </button>

              <button
                onClick={logout}
                className="px-2.5 py-1.5 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition-colors cursor-pointer text-xs font-semibold"
              >
                Sign Out
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <button
                onClick={onOpenSignIn}
                className="px-3 py-1.5 rounded-xl text-slate-300 hover:text-white hover:bg-slate-900 font-semibold transition-colors cursor-pointer"
              >
                Sign In
              </button>

              <button
                onClick={() => onOpenSignUp('INDIVIDUAL')}
                className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-semibold shadow-md shadow-blue-600/20 transition-all cursor-pointer flex items-center gap-1.5"
              >
                <span>Get Started</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
