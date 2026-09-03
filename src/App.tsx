import React, { useState, useEffect } from 'react';
import { Header, CommercialView } from './components/Header';
import { CommercialLanding } from './components/CommercialLanding/CommercialLanding';
import { PricingView } from './components/CommercialLanding/PricingView';
import { HowItWorksView } from './components/CommercialLanding/HowItWorksView';
import { BusinessView } from './components/CommercialLanding/BusinessView';
import { IndividualPortal } from './components/IndividualPortal/IndividualPortal';
import { CustomerPortal } from './components/CustomerPortal/CustomerPortal';
import { SuperAdminPortal } from './components/SuperAdmin/SuperAdminPortal';
import { SuperAdminLogin } from './components/SuperAdmin/SuperAdminLogin';
import { AuthModal } from './components/Auth/AuthModal';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Shield, Lock, ExternalLink } from 'lucide-react';

function PhishGuardApp() {
  const { user, isSuperAdmin } = useAuth();
  const [currentView, setCurrentView] = useState<CommercialView>('landing');
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authModalMode, setAuthModalMode] = useState<'signin' | 'signup'>('signin');
  const [defaultAccountType, setDefaultAccountType] = useState<'INDIVIDUAL' | 'BUSINESS'>('INDIVIDUAL');

  // Super Admin route detection via path or hash
  const [isSuperAdminRoute, setIsSuperAdminRoute] = useState(false);

  useEffect(() => {
    const checkRoute = () => {
      const path = window.location.pathname.toLowerCase();
      const hash = window.location.hash.toLowerCase();
      const isSuperAdminUrl =
        path.includes('superadminbruno') ||
        hash.includes('superadminbruno') ||
        path.includes('superadmin') ||
        hash.includes('superadmin');
      setIsSuperAdminRoute(isSuperAdminUrl);
    };

    checkRoute();
    window.addEventListener('popstate', checkRoute);
    window.addEventListener('hashchange', checkRoute);
    return () => {
      window.removeEventListener('popstate', checkRoute);
      window.removeEventListener('hashchange', checkRoute);
    };
  }, []);

  // When user logs in, route them to their respective portal if on landing view
  useEffect(() => {
    if (user && currentView === 'landing') {
      setCurrentView('portal');
    }
  }, [user]);

  const handleOpenSignIn = () => {
    setAuthModalMode('signin');
    setShowAuthModal(true);
  };

  const handleOpenSignUp = (accountType: 'INDIVIDUAL' | 'BUSINESS' = 'INDIVIDUAL') => {
    setAuthModalMode('signup');
    setDefaultAccountType(accountType);
    setShowAuthModal(true);
  };

  const handleSelectPlan = (plan: 'personal' | 'business' | 'enterprise') => {
    if (plan === 'personal') {
      handleOpenSignUp('INDIVIDUAL');
    } else if (plan === 'business') {
      handleOpenSignUp('BUSINESS');
    } else {
      handleOpenSignUp('BUSINESS');
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-blue-600 selection:text-white flex flex-col">
      {/* Top Header */}
      <Header
        currentView={currentView}
        setCurrentView={setCurrentView}
        onOpenSignIn={handleOpenSignIn}
        onOpenSignUp={handleOpenSignUp}
        isSuperAdminRoute={isSuperAdminRoute}
      />

      {/* Main Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* If user navigated directly to the Super Admin path */}
        {isSuperAdminRoute ? (
          isSuperAdmin ? (
            <SuperAdminPortal />
          ) : (
            <SuperAdminLogin onSuccess={() => setIsSuperAdminRoute(true)} />
          )
        ) : (
          <>
            {/* Commercial Landing */}
            {currentView === 'landing' && (
              <CommercialLanding
                onOpenSignIn={handleOpenSignIn}
                onOpenSignUp={handleOpenSignUp}
                onNavigateToView={(view) => setCurrentView(view)}
              />
            )}

            {/* How It Works Deep-Dive */}
            {currentView === 'how-it-works' && (
              <HowItWorksView onGetStarted={() => handleOpenSignUp('INDIVIDUAL')} />
            )}

            {/* Business Solution */}
            {currentView === 'business' && (
              <BusinessView onStartFleetTrial={() => handleOpenSignUp('BUSINESS')} />
            )}

            {/* Transparent Pricing View */}
            {currentView === 'pricing' && (
              <PricingView onSelectPlan={handleSelectPlan} />
            )}

            {/* User Authenticated Portals */}
            {currentView === 'portal' && (
              <>
                {user ? (
                  user.role === 'INDIVIDUAL' ? (
                    <IndividualPortal />
                  ) : user.role === 'SUPER_ADMIN' ? (
                    <SuperAdminPortal />
                  ) : (
                    <CustomerPortal />
                  )
                ) : (
                  <CommercialLanding
                    onOpenSignIn={handleOpenSignIn}
                    onOpenSignUp={handleOpenSignUp}
                    onNavigateToView={(view) => setCurrentView(view)}
                  />
                )}
              </>
            )}
          </>
        )}
      </main>

      {/* Auth Modal */}
      <AuthModal
        isOpen={showAuthModal}
        onClose={() => setShowAuthModal(false)}
        initialMode={authModalMode}
        defaultAccountType={defaultAccountType}
      />

      {/* Commercial Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-8 mt-16 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2.5">
              <Shield className="w-5 h-5 text-blue-500" />
              <span className="font-bold text-slate-300 text-sm">PhishGuard Security</span>
              <span className="text-slate-600">|</span>
              <span>Autonomous Browser Threat Defense</span>
            </div>

            <div className="flex items-center gap-6">
              <button
                onClick={() => setCurrentView('how-it-works')}
                className="hover:text-slate-300 transition-colors cursor-pointer"
              >
                Architecture
              </button>
              <button
                onClick={() => setCurrentView('pricing')}
                className="hover:text-slate-300 transition-colors cursor-pointer"
              >
                Pricing
              </button>
              <button
                onClick={() => setCurrentView('business')}
                className="hover:text-slate-300 transition-colors cursor-pointer"
              >
                Enterprise
              </button>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-900/80 flex flex-col sm:flex-row items-center justify-between gap-2 text-[11px]">
            <div>
              &copy; {new Date().getFullYear()} PhishGuard Technologies. All rights reserved. Zero URL exfiltration guarantee.
            </div>
            <div className="flex items-center gap-4">
              <span>Manifest V3 Compliant</span>
              <span>•</span>
              <span>Sub-10ms Local Execution</span>
              <span>•</span>
              <span>GDPR / CCPA Ready</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <PhishGuardApp />
    </AuthProvider>
  );
}
