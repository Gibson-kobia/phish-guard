import React, { useState } from 'react';
import { Shield, Lock, ArrowRight, AlertCircle, KeyRound, Mail } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export const SuperAdminLogin: React.FC<{ onSuccess: () => void }> = ({ onSuccess }) => {
  const { login } = useAuth();
  const [emailOrUser, setEmailOrUser] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await login(emailOrUser, password);
      if (res.success) {
        onSuccess();
      } else {
        setError(res.error || 'Access denied: Invalid credentials.');
      }
    } catch (err: any) {
      setError(err?.message || 'Authentication error.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-8 shadow-2xl space-y-6">
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-2xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 mx-auto shadow-md">
            <Lock className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Security Operations Access
          </h1>
          <p className="text-xs text-slate-400">
            Platform Operator & Threat Intelligence Console
          </p>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label htmlFor="superadmin-identifier-input" className="block font-semibold text-slate-300 mb-1.5">
              Operator Identifier or Email
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                id="superadmin-identifier-input"
                type="text"
                required
                autoComplete="username"
                value={emailOrUser}
                onChange={(e) => setEmailOrUser(e.target.value)}
                placeholder="admin@phishguard.security"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          <div>
            <label htmlFor="superadmin-password-input" className="block font-semibold text-slate-300 mb-1.5">
              Security Credential
            </label>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                id="superadmin-password-input"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white rounded-xl font-semibold shadow-lg shadow-indigo-600/20 transition-all cursor-pointer flex items-center justify-center gap-2"
          >
            {loading ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <>
                <span>Authenticate Operator</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </form>

        <div className="pt-4 border-t border-slate-800 text-center">
          <p className="text-[11px] text-slate-500">
            🔒 All operator actions are cryptographically signed and logged in the immutable audit log.
          </p>
        </div>
      </div>
    </div>
  );
};
