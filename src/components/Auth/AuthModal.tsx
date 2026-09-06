import React, { useState } from 'react';
import { Shield, Lock, User, Building2, AlertCircle, X, ArrowRight, Check, Mail, KeyRound } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialMode?: 'signin' | 'signup';
  defaultAccountType?: 'INDIVIDUAL' | 'BUSINESS';
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  initialMode = 'signin',
  defaultAccountType = 'INDIVIDUAL'
}) => {
  const { user, login, signup, logout, forgotPassword } = useAuth();
  const [mode, setMode] = useState<'signin' | 'signup' | 'forgot'>(initialMode);
  const [accountType, setAccountType] = useState<'INDIVIDUAL' | 'BUSINESS'>(defaultAccountType);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMessage(null);

    try {
      if (mode === 'signin') {
        const res = await login(email, password);
        if (res.success) {
          onClose();
        } else {
          setError(res.error || 'Invalid email or password.');
        }
      } else if (mode === 'signup') {
        const res = await signup({
          email,
          password,
          name,
          accountType,
          organizationName: accountType === 'BUSINESS' ? organizationName : undefined
        });
        if (res.success) {
          onClose();
        } else {
          setError(res.error || 'Failed to create account.');
        }
      } else if (mode === 'forgot') {
        const res = await forgotPassword(email);
        setSuccessMessage(res.message);
      }
    } catch (err: any) {
      setError(err?.message || 'An unexpected error occurred.');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setError(null);
    setSuccessMessage(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fade-in">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full shadow-2xl overflow-hidden relative">
        {/* Top Header */}
        <div className="px-6 py-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center text-white shadow-md shadow-blue-500/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">
                {mode === 'signin' && 'Sign In to PhishGuard'}
                {mode === 'signup' && 'Create Your Account'}
                {mode === 'forgot' && 'Reset Password'}
              </h3>
              <p className="text-xs text-slate-400">
                {mode === 'signin' && 'Access your security portal and active devices'}
                {mode === 'signup' && 'Zero-exfiltration browser protection in seconds'}
                {mode === 'forgot' && 'Enter your verified account email'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Currently signed in banner if applicable */}
        {user && (
          <div className="px-6 py-3 bg-blue-950/40 border-b border-blue-900/40 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>Signed in as <strong className="text-white">{user.name}</strong></span>
            </div>
            <button
              onClick={async () => {
                await logout();
                onClose();
              }}
              className="text-rose-400 hover:text-rose-300 hover:underline font-medium cursor-pointer"
            >
              Sign Out
            </button>
          </div>
        )}

        {/* Body Content */}
        <div className="p-6">
          {error && (
            <div className="mb-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center gap-2.5">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {successMessage && (
            <div className="mb-4 p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2.5">
              <Check className="w-4 h-4 flex-shrink-0" />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Mode Selector */}
          {mode !== 'forgot' && (
            <div className="grid grid-cols-2 p-1 bg-slate-950 rounded-xl border border-slate-800 mb-5 text-xs">
              <button
                type="button"
                onClick={() => { setMode('signin'); handleReset(); }}
                className={`py-2 rounded-lg font-semibold transition-all cursor-pointer ${
                  mode === 'signin'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => { setMode('signup'); handleReset(); }}
                className={`py-2 rounded-lg font-semibold transition-all cursor-pointer ${
                  mode === 'signup'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Create Account
              </button>
            </div>
          )}

          {/* Account Type Selector for Sign Up */}
          {mode === 'signup' && (
            <div className="mb-5 space-y-2">
              <label className="block text-xs font-semibold text-slate-300">Account Type</label>
              <div className="grid grid-cols-2 gap-2.5">
                <button
                  type="button"
                  onClick={() => setAccountType('INDIVIDUAL')}
                  className={`p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col gap-1 ${
                    accountType === 'INDIVIDUAL'
                      ? 'bg-blue-500/10 border-blue-500 text-white shadow-sm shadow-blue-500/10'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-1.5 text-xs font-bold text-white">
                    <User className="w-3.5 h-3.5 text-blue-400" />
                    <span>Personal</span>
                  </div>
                  <span className="text-[11px] text-slate-400 leading-tight">
                    Individual & family browser protection
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() => setAccountType('BUSINESS')}
                  className={`p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col gap-1 ${
                    accountType === 'BUSINESS'
                      ? 'bg-blue-500/10 border-blue-500 text-white shadow-sm shadow-blue-500/10'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-1.5 text-xs font-bold text-white">
                    <Building2 className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Business Fleet</span>
                  </div>
                  <span className="text-[11px] text-slate-400 leading-tight">
                    Team MDM push & central telemetry
                  </span>
                </button>
              </div>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'signup' && (
              <div>
                <label htmlFor="auth-modal-name-input" className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Full Name
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="auth-modal-name-input"
                    type="text"
                    required
                    autoComplete="name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Sarah Connor"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
            )}

            {mode === 'signup' && accountType === 'BUSINESS' && (
              <div>
                <label htmlFor="auth-modal-org-name-input" className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Organization / Company Name
                </label>
                <div className="relative">
                  <Building2 className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="auth-modal-org-name-input"
                    type="text"
                    required
                    autoComplete="organization"
                    value={organizationName}
                    onChange={(e) => setOrganizationName(e.target.value)}
                    placeholder="e.g. Acme Corp"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
            )}

            <div>
              <label htmlFor="auth-modal-email-input" className="block text-xs font-semibold text-slate-300 mb-1.5">
                Work or Personal Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  id="auth-modal-email-input"
                  type="email"
                  required
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@company.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            {mode !== 'forgot' && (
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label htmlFor="auth-modal-password-input" className="text-xs font-semibold text-slate-300">
                    Password
                  </label>
                  {mode === 'signin' && (
                    <button
                      type="button"
                      onClick={() => { setMode('forgot'); handleReset(); }}
                      className="text-[11px] text-blue-400 hover:text-blue-300 hover:underline cursor-pointer"
                    >
                      Forgot password?
                    </button>
                  )}
                </div>
                <div className="relative">
                  <KeyRound className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    id="auth-modal-password-input"
                    type="password"
                    required
                    minLength={8}
                    autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
                {mode === 'signup' && (
                  <p className="text-[11px] text-slate-500 mt-1">Must be at least 8 characters.</p>
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/20 transition-all cursor-pointer flex items-center justify-center gap-2 mt-2"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <>
                  <span>
                    {mode === 'signin' && 'Sign In'}
                    {mode === 'signup' && 'Get Started'}
                    {mode === 'forgot' && 'Send Reset Link'}
                  </span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>

          {mode === 'forgot' && (
            <div className="mt-4 text-center">
              <button
                type="button"
                onClick={() => { setMode('signin'); handleReset(); }}
                className="text-xs text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                Back to Sign In
              </button>
            </div>
          )}

          <div className="mt-6 pt-4 border-t border-slate-800/80 text-center">
            <p className="text-[11px] text-slate-500">
              🔒 PhishGuard uses zero-knowledge client execution. Password credentials are scrypt-derived.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
