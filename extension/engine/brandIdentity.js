const KNOWN_BRANDS = [
  {
    id: "vinted",
    name: "Vinted",
    canonicalDomains: [
      "vinted.com",
      "vinted.fr",
      "vinted.de",
      "vinted.co.uk",
      "vinted.es",
      "vinted.it",
      "vinted.pl",
      "vinted.lt",
      "vinted.cz",
      "vinted.nl",
      "vinted.be",
      "vinted.at",
      "vinted.se"
    ],
    aliases: ["vinted", "vinted uk", "vinted marketplace", "vinted fr", "vinted de"],
    keywords: ["vinted", "vintedmarket", "second hand", "wardrobe", "vinted balance"],
    category: "ECOMMERCE"
  },
  {
    id: "jumia",
    name: "Jumia",
    canonicalDomains: [
      "jumia.com",
      "jumia.com.ng",
      "jumia.co.ke",
      "jumia.ma",
      "jumia.ci",
      "jumia.ug",
      "jumia.com.gh",
      "jumia.com.eg"
    ],
    aliases: ["jumia", "jumia store", "jumia online", "jumia market"],
    keywords: ["jumia", "jumia store", "jumia market", "jumia pay"],
    category: "ECOMMERCE"
  },
  {
    id: "paypal",
    name: "PayPal",
    canonicalDomains: ["paypal.com", "paypal-objects.com", "paypal.me", "paypal-community.com"],
    knownAuthDomains: ["www.paypal.com/signin", "paypal.com/auth"],
    knownPaymentDomains: ["checkout.paypal.com", "paypal.com/checkout"],
    aliases: ["paypal", "paypal inc", "paypal security"],
    keywords: ["paypal", "paypaii", "paypai", "paypal balance", "send money"],
    category: "FINANCIAL"
  },
  {
    id: "google",
    name: "Google / Gmail",
    canonicalDomains: ["google.com", "google.co.uk", "google.ca", "gmail.com", "accounts.google.com", "gstatic.com", "googleusercontent.com"],
    knownAuthDomains: ["accounts.google.com"],
    aliases: ["google", "gmail", "google workspace", "google account"],
    keywords: ["google", "gmail", "g00gle", "goog1e", "google sign in"],
    category: "TECH"
  },
  {
    id: "microsoft",
    name: "Microsoft / Outlook / Office",
    canonicalDomains: ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com", "msn.com", "sharepoint.com"],
    knownAuthDomains: ["login.microsoftonline.com", "login.live.com"],
    aliases: ["microsoft", "outlook", "office 365", "microsoft 365"],
    keywords: ["microsoft", "outlook", "office365", "micros0ft", "ms-online"],
    category: "TECH"
  },
  {
    id: "apple",
    name: "Apple / iCloud",
    canonicalDomains: ["apple.com", "icloud.com", "appleid.apple.com", "itunes.com"],
    knownAuthDomains: ["appleid.apple.com"],
    aliases: ["apple", "icloud", "apple id"],
    keywords: ["apple", "icloud", "appl-id", "apple-id", "apple id sign in"],
    category: "TECH"
  },
  {
    id: "amazon",
    name: "Amazon",
    canonicalDomains: ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com", "media-amazon.com"],
    aliases: ["amazon", "aws", "amazon prime"],
    keywords: ["amazon", "amaz0n", "amazon prime", "amazon order"],
    category: "ECOMMERCE"
  },
  {
    id: "netflix",
    name: "Netflix",
    canonicalDomains: ["netflix.com", "nflxvideo.net", "netflix.net"],
    aliases: ["netflix", "netflix streaming"],
    keywords: ["netflix", "netf1ix", "netflix account", "netflix billing"],
    category: "TECH"
  },
  {
    id: "chase",
    name: "Chase Bank",
    canonicalDomains: ["chase.com", "jpmorganchase.com"],
    aliases: ["chase", "jpmorgan chase", "chase online"],
    keywords: ["chase", "chase bank", "chase online", "jpmorgan"],
    category: "FINANCIAL"
  },
  {
    id: "wellsfargo",
    name: "Wells Fargo",
    canonicalDomains: ["wellsfargo.com"],
    aliases: ["wells fargo", "wf bank"],
    keywords: ["wellsfargo", "wells fargo", "wf online"],
    category: "FINANCIAL"
  },
  {
    id: "bankofamerica",
    name: "Bank of America",
    canonicalDomains: ["bankofamerica.com", "bofa.com"],
    aliases: ["bank of america", "bofa"],
    keywords: ["bankofamerica", "bofa", "bofa online banking"],
    category: "FINANCIAL"
  },
  {
    id: "meta",
    name: "Meta / Facebook / Instagram",
    canonicalDomains: ["facebook.com", "fb.com", "instagram.com", "meta.com", "messenger.com", "whatsapp.com"],
    aliases: ["facebook", "instagram", "meta", "whatsapp"],
    keywords: ["facebook", "instagram", "meta", "fb login"],
    category: "SOCIAL"
  },
  {
    id: "binance",
    name: "Binance",
    canonicalDomains: ["binance.com", "binance.us", "bnbstatic.com"],
    aliases: ["binance", "binance exchange"],
    keywords: ["binance", "binance wallet", "bnb"],
    category: "CRYPTO"
  },
  {
    id: "coinbase",
    name: "Coinbase",
    canonicalDomains: ["coinbase.com", "pro.coinbase.com"],
    aliases: ["coinbase", "coinbase exchange"],
    keywords: ["coinbase", "c0inbase", "coinbase wallet"],
    category: "CRYPTO"
  },
  {
    id: "github",
    name: "GitHub",
    canonicalDomains: ["github.com", "github.io", "githubusercontent.com", "github.blog"],
    aliases: ["github", "github inc"],
    keywords: ["github", "g1thub", "github sign in"],
    category: "TECH"
  },
  {
    id: "stripe",
    name: "Stripe",
    canonicalDomains: ["stripe.com", "checkout.stripe.com", "stripe.network"],
    aliases: ["stripe", "stripe payments"],
    keywords: ["stripe", "stripe checkout", "powered by stripe"],
    category: "FINANCIAL"
  },
  {
    id: "steam",
    name: "Steam / Valve",
    canonicalDomains: ["steampowered.com", "steamcommunity.com", "valvesoftware.com"],
    aliases: ["steam", "valve", "steam community"],
    keywords: ["steam", "steam community", "steam login", "steam guard"],
    category: "TECH"
  },
  {
    id: "docusign",
    name: "DocuSign",
    canonicalDomains: ["docusign.com", "docusign.net"],
    aliases: ["docusign", "docusign inc"],
    keywords: ["docusign", "sign document", "docusign envelope"],
    category: "PRODUCTIVITY"
  },
  {
    id: "dhl",
    name: "DHL Express",
    canonicalDomains: ["dhl.com", "dhl.de", "dhl.co.uk", "dhl-express.com"],
    aliases: ["dhl", "dhl express"],
    keywords: ["dhl", "dhl tracking", "dhl delivery", "shipment delivery"],
    category: "LOGISTICS"
  }
];
const FREE_HOSTING_PROVIDERS = {
  "netlify.app": "Netlify App Hosting",
  "vercel.app": "Vercel Platform",
  "firebaseapp.com": "Google Firebase",
  "web.app": "Google Firebase Web",
  "pages.dev": "Cloudflare Pages",
  "workers.dev": "Cloudflare Workers",
  "github.io": "GitHub Pages",
  "gitlab.io": "GitLab Pages",
  "glitch.me": "Glitch Hosting",
  "render.com": "Render Cloud",
  "onrender.com": "Render Cloud App",
  "surge.sh": "Surge Static Web",
  "herokuapp.com": "Heroku Cloud",
  "supabase.co": "Supabase Storage/Auth",
  "s3.amazonaws.com": "AWS S3 Bucket",
  "blob.core.windows.net": "Azure Blob Storage",
  "000webhostapp.com": "000Webhost Free Tier",
  "weebly.com": "Weebly Free Site",
  "wixsite.com": "Wix Free Subdomain",
  "sites.google.com": "Google Sites Free",
  "godaddysites.com": "GoDaddy Free Site Builder"
};
function extractRegisteredDomain(hostname) {
  const clean = hostname.toLowerCase().trim();
  const parts = clean.split(".");
  if (parts.length <= 2) return clean;
  const multiPartTlds = [
    "co.uk",
    "com.au",
    "co.nz",
    "co.jp",
    "com.br",
    "co.za",
    "gov.uk",
    "edu.au",
    "com.sg",
    "co.il",
    "com.ng",
    "co.ke",
    "com.gh",
    "com.eg",
    "net.au",
    "org.uk"
  ];
  const lastTwo = parts.slice(-2).join(".");
  if (multiPartTlds.includes(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}
function inferBrandIdentity(hostname, pageTitle, visibleTokens = [], formMeta, socialMeta, customBrands = KNOWN_BRANDS) {
  const cleanHostname = hostname.toLowerCase().trim();
  const registeredDomain = extractRegisteredDomain(cleanHostname);
  for (const brand of customBrands) {
    const isCanonical = brand.canonicalDomains.some((d) => cleanHostname === d || cleanHostname.endsWith("." + d));
    if (isCanonical) {
      return {
        candidateName: brand.name,
        confidence: 0.99,
        evidence: [`Matches verified canonical domain ${cleanHostname}`],
        source: "KNOWN_REGISTRY",
        isKnownBrand: true,
        knownBrandId: brand.id,
        canonicalDomains: brand.canonicalDomains
      };
    }
    const brandTokens = [brand.id, ...brand.keywords.map((k) => k.replace(/\s+/g, ""))];
    let hostMatch = false;
    let matchingToken = "";
    for (const token of brandTokens) {
      if (token.length >= 3 && cleanHostname.includes(token)) {
        hostMatch = true;
        matchingToken = token;
        break;
      }
    }
    let contextMatch = false;
    if (pageTitle && (pageTitle.toLowerCase().includes(brand.name.toLowerCase()) || brand.keywords.some((k) => pageTitle.toLowerCase().includes(k)))) {
      contextMatch = true;
    }
    if (visibleTokens.some((t) => t.toLowerCase() === brand.name.toLowerCase() || brand.keywords.includes(t.toLowerCase()))) {
      contextMatch = true;
    }
    if (hostMatch || contextMatch) {
      const evidence = [];
      if (hostMatch) evidence.push(`Hostname contains brand token "${matchingToken}"`);
      if (contextMatch) evidence.push(`Page title or heading references brand "${brand.name}"`);
      return {
        candidateName: brand.name,
        confidence: hostMatch && contextMatch ? 0.95 : 0.85,
        evidence,
        source: "KNOWN_REGISTRY",
        isKnownBrand: true,
        knownBrandId: brand.id,
        canonicalDomains: brand.canonicalDomains
      };
    }
  }
  const genericCandidates = [];
  if (pageTitle && pageTitle.trim().length > 2) {
    const titleClean = pageTitle.trim();
    const titleParts = titleClean.split(/\s*[-–—|:]\s*/).filter(Boolean);
    if (titleParts.length > 0) {
      const candidateTitleName = titleParts[0].trim();
      const isGenericNoise = /^(login|sign\s*in|welcome|home|index|untitled|page|loading|portal)$/i.test(candidateTitleName);
      if (!isGenericNoise && candidateTitleName.length >= 3 && candidateTitleName.length <= 35) {
        genericCandidates.push({
          name: candidateTitleName,
          confidence: 0.7,
          evidence: [`Document title prominently presents entity "${candidateTitleName}"`],
          source: "DOCUMENT_TITLE"
        });
      }
    }
  }
  let isFreeHosting = false;
  const hasFormsOrUrgency = !!(formMeta?.hasPasswordInput || formMeta?.hasCreditCardInput || formMeta?.has2FAInput || socialMeta?.hasUrgencyLanguage || socialMeta?.hasCredentialVerificationPrompt);
  for (const providerDomain of Object.keys(FREE_HOSTING_PROVIDERS)) {
    if (cleanHostname.endsWith(providerDomain)) {
      isFreeHosting = true;
      const subdomain = cleanHostname.replace("." + providerDomain, "").replace(/\./g, "-");
      const cleanedToken = subdomain.replace(/-(login|verify|security|portal|auth|update|support|checkout|payment|app)$/i, "").replace(/^(secure|my|login|auth|portal)-/i, "");
      const hasSecurityKeywords = /-(login|verify|security|portal|auth|update|support|checkout|payment)$/i.test(subdomain) || /^(secure|login|auth|portal)-/i.test(subdomain);
      if (cleanedToken.length >= 3 && !/^(www|app|test|dev|demo|stage|prod|api)$/i.test(cleanedToken)) {
        if (hasSecurityKeywords || hasFormsOrUrgency) {
          const formattedName = cleanedToken.charAt(0).toUpperCase() + cleanedToken.slice(1);
          genericCandidates.push({
            name: formattedName,
            confidence: 0.75,
            evidence: [`Free hosting subdomain "${subdomain}" claims identity "${formattedName}"`],
            source: "HOSTNAME_TOKEN"
          });
        }
      }
      break;
    }
  }
  for (const token of visibleTokens) {
    const authMatch = token.match(/(?:sign\s*in\s*to|log\s*in\s*to|welcome\s*to|verify\s*your)\s+([A-Za-z0-9\s]{3,25})/i);
    if (authMatch && authMatch[1]) {
      const extractedBrand = authMatch[1].trim();
      if (!/^(account|portal|website|page|service|system)$/i.test(extractedBrand)) {
        genericCandidates.push({
          name: extractedBrand,
          confidence: 0.8,
          evidence: [`Authentication heading declares "${token}"`],
          source: "HEADINGS"
        });
      }
    }
  }
  if (genericCandidates.length === 0) {
    return null;
  }
  genericCandidates.sort((a, b) => b.confidence - a.confidence);
  const best = genericCandidates[0];
  const inferredClean = best.name.toLowerCase().replace(/[^a-z0-9]/g, "");
  const inferredCanonical = `${inferredClean}.com`;
  return {
    candidateName: best.name,
    confidence: best.confidence,
    evidence: best.evidence,
    source: best.source,
    isKnownBrand: false,
    canonicalDomains: [inferredCanonical]
  };
}
function evaluateBrandDomainMismatch(hostname, candidate) {
  if (!candidate) return null;
  const cleanHostname = hostname.toLowerCase().trim();
  const registeredDomain = extractRegisteredDomain(cleanHostname);
  let matchedFreeHosting;
  for (const [providerDomain, providerName] of Object.entries(FREE_HOSTING_PROVIDERS)) {
    if (cleanHostname.endsWith(providerDomain) || cleanHostname === providerDomain) {
      matchedFreeHosting = providerName;
      break;
    }
  }
  const isOfficial = candidate.canonicalDomains.some(
    (canonical) => cleanHostname === canonical || cleanHostname.endsWith("." + canonical) || registeredDomain === canonical
  );
  if (isOfficial) {
    return {
      candidate,
      isOfficial: true,
      isSubdomainAbuse: false,
      isFreeHostingAbuse: false,
      isCombosquat: false,
      details: `Official verified ${candidate.candidateName} domain (${cleanHostname}).`
    };
  }
  if (matchedFreeHosting) {
    return {
      candidate,
      isOfficial: false,
      isSubdomainAbuse: true,
      isFreeHostingAbuse: true,
      isCombosquat: true,
      freeHostingProvider: matchedFreeHosting,
      details: `Page represents ${candidate.candidateName} hosted on third-party cloud platform (${matchedFreeHosting}) rather than official domain.`
    };
  }
  const isCombosquat = cleanHostname.includes(candidate.candidateName.toLowerCase().replace(/[^a-z0-9]/g, ""));
  return {
    candidate,
    isOfficial: false,
    isSubdomainAbuse: cleanHostname.split(".").length > 2,
    isFreeHostingAbuse: false,
    isCombosquat,
    details: `Page claims identity "${candidate.candidateName}" but is hosted on unrelated domain (${cleanHostname}).`
  };
}
function evaluateBrandImpersonation(hostname, pageTitle, visibleTokens = [], formMeta, socialMeta, customBrands = KNOWN_BRANDS) {
  const candidate = inferBrandIdentity(hostname, pageTitle, visibleTokens, formMeta, socialMeta, customBrands);
  if (!candidate) return null;
  const evalResult = evaluateBrandDomainMismatch(hostname, candidate);
  if (!evalResult) return null;
  const matchedBrand = customBrands.find((b) => b.name === candidate.candidateName) || {
    id: candidate.candidateName.toLowerCase().replace(/[^a-z0-9]/g, ""),
    name: candidate.candidateName,
    canonicalDomains: candidate.canonicalDomains,
    aliases: [candidate.candidateName],
    keywords: [candidate.candidateName.toLowerCase()],
    category: "OTHER"
  };
  return {
    brand: matchedBrand,
    isOfficial: evalResult.isOfficial,
    isSubdomainAbuse: evalResult.isSubdomainAbuse,
    isFreeHostingAbuse: evalResult.isFreeHostingAbuse,
    isCombosquat: evalResult.isCombosquat,
    isHomoglyphOrTypo: false,
    freeHostingProvider: evalResult.freeHostingProvider,
    details: evalResult.details
  };
}
export {
  FREE_HOSTING_PROVIDERS,
  KNOWN_BRANDS,
  evaluateBrandDomainMismatch,
  evaluateBrandImpersonation,
  extractRegisteredDomain,
  inferBrandIdentity
};
