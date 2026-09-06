import React, { createContext, useContext, useState, useEffect } from 'react';
import { Organization } from '../core/types';

export interface UserProfile {
  id: string;
  username: string;
  name: string;
  email: string;
  role: 'SUPER_ADMIN' | 'ORG_ADMIN' | 'INDIVIDUAL' | 'READ_ONLY';
  organizationId?: string;
  organizationName?: string;
  plan?: string;
  planStatus?: string;
  billingInterval?: string;
}

interface SignupParams {
  email: string;
  password?: string;
  name?: string;
  accountType: 'INDIVIDUAL' | 'BUSINESS';
  organizationName?: string;
  plan?: string;
}

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  loading: boolean;
  isAuthenticated: boolean;
  isSuperAdmin: boolean;
  isCustomerAdmin: boolean;
  isIndividual: boolean;
  activeOrgId: string;
  activeOrg: Organization | null;
  organizations: Organization[];
  login: (emailOrUsername: string, password?: string) => Promise<{ success: boolean; error?: string }>;
  signup: (params: SignupParams) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  forgotPassword: (email: string) => Promise<{ success: boolean; message: string }>;
  switchOrganization: (orgId: string) => Promise<void>;
  refreshOrganizations: () => Promise<void>;
  authFetch: (url: string, options?: RequestInit) => Promise<Response>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_STORAGE_KEY = 'phishguard_auth_token';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_STORAGE_KEY));
  const [user, setUser] = useState<UserProfile | null>(null);
  const [activeOrg, setActiveOrg] = useState<Organization | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);

  const authFetch = async (url: string, options: RequestInit = {}): Promise<Response> => {
    const headers = new Headers(options.headers || {});
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
      headers.set('X-PhishGuard-Auth-Token', token);
    }
    return fetch(url, {
      ...options,
      credentials: options.credentials || 'include',
      headers
    });
  };

  const fetchProfile = async (currentToken?: string | null) => {
    try {
      const headers: Record<string, string> = {};
      if (currentToken) {
        headers['Authorization'] = `Bearer ${currentToken}`;
        headers['X-PhishGuard-Auth-Token'] = currentToken;
      }
      const res = await fetch('/api/auth/me', {
        credentials: 'include',
        headers
      });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        if (data.organization) {
          setActiveOrg(data.organization);
        }
        return data.user;
      } else {
        // Not authenticated
        localStorage.removeItem(TOKEN_STORAGE_KEY);
        setToken(null);
        setUser(null);
      }
    } catch (err) {
      console.warn('Failed to fetch user profile:', err);
    }
    return null;
  };

  const refreshOrganizations = async () => {
    try {
      const res = await authFetch('/api/admin/organizations');
      if (res.ok) {
        const data = await res.json();
        const rawOrgs: Organization[] = data.organizations || [];
        const uniqueOrgs = Array.from(new Map(rawOrgs.map(o => [o.organizationId, o])).values());
        setOrganizations(uniqueOrgs);
      }
    } catch (err) {
      console.warn('Failed to fetch organizations:', err);
    }
  };

  useEffect(() => {
    const initAuth = async () => {
      // Authenticate via HttpOnly cookie or stored token
      const fetchedUser = await fetchProfile(token);
      if (fetchedUser?.role === 'SUPER_ADMIN') {
        await refreshOrganizations();
      }
      setLoading(false);
    };
    initAuth();
  }, []);

  const login = async (emailOrUsername: string, password?: string) => {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: emailOrUsername, username: emailOrUsername, password })
      });
      let data: any = null;
      try {
        data = await res.json();
      } catch (parseErr) {
        return { success: false, error: `Authentication service returned error (${res.status}). Please try again.` };
      }

      if (res.ok && data.success && data.token) {
        setToken(data.token);
        localStorage.setItem(TOKEN_STORAGE_KEY, data.token);
        setUser(data.user);
        if (data.user?.organizationId) {
          try {
            const orgRes = await fetch(`/api/organizations/${data.user.organizationId}`, {
              headers: { Authorization: `Bearer ${data.token}` }
            });
            if (orgRes.ok) {
              const orgData = await orgRes.json();
              setActiveOrg(orgData.organization);
            }
          } catch (orgErr) {
            console.warn('Failed to fetch user organization:', orgErr);
          }
        }
        if (data.user?.role === 'SUPER_ADMIN') {
          await refreshOrganizations();
        }
        return { success: true };
      } else {
        return { success: false, error: data?.error || 'Invalid credentials' };
      }
    } catch (err: any) {
      return { success: false, error: err?.message || 'Network error' };
    }
  };

  const signup = async (params: SignupParams) => {
    try {
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params)
      });
      let data: any = null;
      try {
        data = await res.json();
      } catch (parseErr) {
        return { success: false, error: `Registration service returned error (${res.status}). Please try again.` };
      }

      if (res.ok && data.success && data.token) {
        setToken(data.token);
        localStorage.setItem(TOKEN_STORAGE_KEY, data.token);
        setUser(data.user);
        if (data.user?.organizationId) {
          try {
            const orgRes = await fetch(`/api/organizations/${data.user.organizationId}`, {
              credentials: 'include',
              headers: { Authorization: `Bearer ${data.token}` }
            });
            if (orgRes.ok) {
              const orgData = await orgRes.json();
              setActiveOrg(orgData.organization);
            }
          } catch (orgErr) {
            console.warn('Failed to fetch user organization:', orgErr);
          }
        }
        return { success: true };
      } else {
        return { success: false, error: data?.error || 'Failed to create account' };
      }
    } catch (err: any) {
      return { success: false, error: err?.message || 'Network error' };
    }
  };

  const forgotPassword = async (email: string) => {
    try {
      const res = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const data = await res.json();
      return { success: true, message: data.message || 'Password reset email sent if account exists.' };
    } catch (err: any) {
      return { success: false, message: 'Password recovery request processed.' };
    }
  };

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });
    } catch (err) {
      // ignore
    } finally {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      setToken(null);
      setUser(null);
      setActiveOrg(null);
    }
  };

  const switchOrganization = async (orgId: string) => {
    if (!token) return;
    try {
      const orgRes = await authFetch(`/api/organizations/${orgId}`);
      if (orgRes.ok) {
        const data = await orgRes.json();
        setActiveOrg(data.organization);
      }
    } catch (err) {
      console.warn('Failed to switch organization:', err);
    }
  };

  const isSuperAdmin = user?.role === 'SUPER_ADMIN';
  const isCustomerAdmin = user?.role === 'ORG_ADMIN' || user?.role === 'READ_ONLY';
  const isIndividual = user?.role === 'INDIVIDUAL';
  const activeOrgId = user?.organizationId || activeOrg?.organizationId || '';

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        isAuthenticated: !!user,
        isSuperAdmin,
        isCustomerAdmin,
        isIndividual,
        activeOrgId,
        activeOrg,
        organizations,
        login,
        signup,
        logout,
        forgotPassword,
        switchOrganization,
        refreshOrganizations,
        authFetch
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
