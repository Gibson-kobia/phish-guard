/**
 * PhishGuard Trusted Identity & Payment Providers
 * 
 * Defines legitimate third-party OAuth/SSO identity providers and payment processors.
 * Prevents false positive cross-origin alerts when authentic federated login or payment
 * flows occur on legitimate websites.
 */

export interface TrustedProvider {
  id: string;
  name: string;
  category: 'AUTH_OAUTH' | 'PAYMENT_GATEWAY' | 'IDENTITY_SSO';
  canonicalDomains: string[];
  actionHostPatterns: RegExp[];
  notes: string;
}

export const TRUSTED_IDENTITY_PROVIDERS: TrustedProvider[] = [
  {
    id: 'google_auth',
    name: 'Google Identity / Sign-In',
    category: 'AUTH_OAUTH',
    canonicalDomains: ['accounts.google.com', 'google.com', 'googleapis.com', 'gstatic.com'],
    actionHostPatterns: [
      /^accounts\.google\.com$/,
      /^oauth2\.googleapis\.com$/,
      /^apis\.google\.com$/
    ],
    notes: 'Official Google OAuth 2.0 & Sign-In with Google endpoints'
  },
  {
    id: 'microsoft_auth',
    name: 'Microsoft Identity / Azure AD',
    category: 'AUTH_OAUTH',
    canonicalDomains: ['login.microsoftonline.com', 'login.live.com', 'microsoft.com', 'account.live.com'],
    actionHostPatterns: [
      /^login\.microsoftonline\.com$/,
      /^login\.live\.com$/,
      /^account\.live\.com$/
    ],
    notes: 'Official Microsoft & Office 365 single sign-on endpoints'
  },
  {
    id: 'apple_auth',
    name: 'Sign in with Apple',
    category: 'AUTH_OAUTH',
    canonicalDomains: ['appleid.apple.com', 'apple.com'],
    actionHostPatterns: [
      /^appleid\.apple\.com$/
    ],
    notes: 'Official Apple ID authentication endpoint'
  },
  {
    id: 'github_auth',
    name: 'GitHub OAuth',
    category: 'AUTH_OAUTH',
    canonicalDomains: ['github.com'],
    actionHostPatterns: [
      /^github\.com$/
    ],
    notes: 'Official GitHub OAuth application authorization endpoint'
  },
  {
    id: 'auth0',
    name: 'Auth0 by Okta',
    category: 'IDENTITY_SSO',
    canonicalDomains: ['auth0.com', 'okta.com'],
    actionHostPatterns: [
      /^[a-zA-Z0-9-]+\.auth0\.com$/,
      /^[a-zA-Z0-9-]+\.guardian\.auth0\.com$/
    ],
    notes: 'Enterprise customer identity provider'
  },
  {
    id: 'okta',
    name: 'Okta Enterprise SSO',
    category: 'IDENTITY_SSO',
    canonicalDomains: ['okta.com', 'oktapreview.com'],
    actionHostPatterns: [
      /^[a-zA-Z0-9-]+\.okta\.com$/,
      /^[a-zA-Z0-9-]+\.oktapreview\.com$/
    ],
    notes: 'Enterprise single sign-on federation'
  }
];

export const TRUSTED_PAYMENT_PROVIDERS: TrustedProvider[] = [
  {
    id: 'stripe_checkout',
    name: 'Stripe Payments',
    category: 'PAYMENT_GATEWAY',
    canonicalDomains: ['stripe.com', 'checkout.stripe.com', 'stripe.network'],
    actionHostPatterns: [
      /^checkout\.stripe\.com$/,
      /^api\.stripe\.com$/,
      /^m\.stripe\.network$/,
      /^js\.stripe\.com$/
    ],
    notes: 'Official Stripe Checkout and tokenization infrastructure'
  },
  {
    id: 'paypal_checkout',
    name: 'PayPal Commerce',
    category: 'PAYMENT_GATEWAY',
    canonicalDomains: ['paypal.com', 'paypalobjects.com'],
    actionHostPatterns: [
      /^(www\.)?paypal\.com$/,
      /^api\.paypal\.com$/,
      /^c\.paypal\.com$/
    ],
    notes: 'Official PayPal Express Checkout and payment capture'
  },
  {
    id: 'square_payments',
    name: 'Square / Block',
    category: 'PAYMENT_GATEWAY',
    canonicalDomains: ['squareup.com', 'square.com'],
    actionHostPatterns: [
      /^[a-zA-Z0-9-]+\.squareup\.com$/,
      /^api\.squareup\.com$/
    ],
    notes: 'Official Square merchant payment processor'
  },
  {
    id: 'shopify_payments',
    name: 'Shopify Checkout',
    category: 'PAYMENT_GATEWAY',
    canonicalDomains: ['shopify.com', 'myshopify.com'],
    actionHostPatterns: [
      /^[a-zA-Z0-9-]+\.myshopify\.com$/,
      /^checkout\.shopify\.com$/
    ],
    notes: 'Official Shopify hosted checkout platform'
  }
];

/**
 * Helper to check if a destination host belongs to a legitimate federated identity or payment provider
 */
export function isTrustedFederatedProvider(destinationHost: string): { isTrusted: boolean; provider?: TrustedProvider } {
  if (!destinationHost) return { isTrusted: false };
  const cleanHost = destinationHost.toLowerCase().trim();

  for (const provider of [...TRUSTED_IDENTITY_PROVIDERS, ...TRUSTED_PAYMENT_PROVIDERS]) {
    for (const pattern of provider.actionHostPatterns) {
      if (pattern.test(cleanHost)) {
        return { isTrusted: true, provider };
      }
    }
  }

  return { isTrusted: false };
}
