# PhishGuard

Privacy-focused Chrome extension for detecting phishing, typosquatting, and suspicious credential forms in real time.

---

## Overview

Modern credential phishing and identity theft attacks increasingly rely on lookalike domains, brand spoofing on multi-tenant cloud hosting, character substitutions (homoglyphs), and cross-origin credential harvesters. Traditional protection models relying solely on static blacklists frequently fail against ephemeral zero-day attack infrastructure.

**PhishGuard** is a client-side browser security extension built on Chrome Manifest V3. It inspects page structures, domain entropy, character distances, and DOM form targets entirely inside the browser to identify and intercept deceptive pages before credentials can be exfiltrated.

---

## Key Capabilities

* **Homoglyph & Typosquatting Detection**: Normalizes visual character substitutions (e.g. `1` $\rightarrow$ `l`, `0` $\rightarrow$ `o`, `vv` $\rightarrow$ `w`, `rn` $\rightarrow$ `m`) and evaluates Damerau-Levenshtein edit distances against protected canonical brand domains.
* **Combosquatting Detection**: Identifies unauthorized brand keywords combined with deceptive prefixes or suffixes (e.g. `secure-`, `-verify`, `-login`) on unverified domains.
* **URL & Domain Structural Analysis**: Detects bare IPv4, IPv6, octal, and integer hostnames; RFC 3986 userinfo authentication spoofing (`https://brand@attacker.com`); and anomalous subdomain nesting.
* **Entropy Analysis**: Measures Shannon entropy on domain names and subdomains to flag randomized or algorithmically generated domains (DGAs).
* **Punycode IDN Detection**: Decodes Internationalized Domain Names (`xn--`) to flag mixed-script homograph attacks.
* **TLD Risk Analysis**: Evaluates high-risk and top-level abuse domains commonly leveraged for short-lived phishing campaigns.
* **DOM & Credential Form Inspection**: Inspects standard and open Shadow DOM structures for sensitive input fields (passwords, payment cards, SSNs, 2FA/OTP tokens).
* **Cross-Origin Credential Target Detection**: Flags forms configured to transmit entered credentials to third-party endpoints distinct from the hosting origin.
* **Threat Scoring & Correlation Model**: Computes a normalized 0–100 risk score and categorizes threats into 5 distinct verdicts (`SAFE`, `LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK`, `DANGEROUS`).
* **In-Page Security Warnings**: Displays informative, non-destructive banners and pre-flight form interception modals on high-risk pages.
* **Configurable Sensitivity**: Lets users adjust detection sensitivity, manage local allowlists/blocklists, and customize threshold limits via the Options interface.
* **Privacy-Focused Processing**: All primary heuristic inspections run locally inside the browser extension without logging keystrokes or exfiltrating user credentials.

---

## Privacy & Security

* **Local Inspection**: All URL heuristics, character calculations, and DOM form inspections are performed locally in the user's browser runtime.
* **Zero Form Value Capturing**: Content scripts never capture, inspect, or store entered passwords, keystrokes, credit card numbers, OTPs, or form input values. Only structural HTML element types and form actions are analyzed.
* **Safe DOM Operations**: Warning banners, dialogs, and popups construct UI using strict DOM nodes and `textContent` rather than arbitrary HTML injection to prevent DOM-based XSS risks.
* **Permissions & Justifications**:
  * `storage`: Persists local user settings, sensitivity preferences, custom allowlists, blocklists, and local scan history.
  * `activeTab`: Queries active tab metadata when the user opens the toolbar popup.
  * `webNavigation`: Tracks top-level navigation hops to detect multi-step redirect chains.
  * `downloads`: Correlates executable file extensions (`.exe`, `.msi`, `.scr`, `.bat`) with active origin risk levels.
  * `host_permissions: ["<all_urls>"]`: Enables content script inspection of DOM structures and injection of safety warning banners across visited web pages.

---

## Architecture

PhishGuard maintains its core detection logic in TypeScript (`src/core/`), which serves as the canonical reference for the standalone browser extension (`extension/`) and the development test harness.

```
┌────────────────────────────────────────────────────────┐
│                   Web Page (Tab)                       │
│  - DOM Forms / Shadow DOM                              │
│  - Navigation URLs & Hops                              │
└───────────────────▲────────────────────────────────────┘
                    │
            Content Script
      (DOM Scanner & Banner Injector)
                    │
                    ▼ (chrome.runtime.sendMessage)
┌────────────────────────────────────────────────────────┐
│        Background Service Worker (Manifest V3)         │
│  - Heuristic Engine Orchestration                      │
│  - Badge & Navigation Listener                         │
│  - chrome.storage.local (Settings & History)           │
└───────────▲────────────────────────────────▲───────────┘
            │                                │
      Action Popup                      Options UI
 (Overview, Timeline, History)      (Rules, Allowlist, Sliders)
```

* **Core Engine (`src/core/`)**: Houses the heuristic calculators (URL parsing, homoglyphs, brand identity, DOM form analysis, and scoring).
* **Extension Runtime (`extension/`)**: Standalone Manifest V3 extension containing the background service worker, content scripts, popup interface, options page, and warning interstitials.
* **Optional Companion Dashboard (`src/components/`, `server.ts`)**: Development harness and local SOC test bench for simulating telemetry ingestion and reviewing incidents.

---

## Detection Model

Each analyzed web page is evaluated across multiple independent heuristic dimensions. Rather than relying on rigid single-flag triggers, PhishGuard calculates category-weighted scores with compound risk multipliers:

1. **Brand Identity & Domain Match**: Verified canonical domains receive dampening bonuses to prevent false positives; unauthorized brand matching on free/cloud hosting triggers significant risk penalties.
2. **Form Sensitivity**: Presence of password or payment inputs on unverified origins elevates base risk.
3. **Cross-Origin Discrepancy**: Forms posting credentials to external origins are heavily flagged.
4. **Infrastructure & URL Structure**: High-entropy subdomains, bare IP addresses, high-risk TLDs, and IDN homoglyphs contribute weighted risk points.

### Verdict Classification
* **SAFE (0–19)**: Clean baseline; standard verified websites.
* **LOW RISK (20–39)**: Minor structural anomalies without credential collection.
* **SUSPICIOUS (40–69)**: Multiple heuristic flags; advisory indicators displayed.
* **HIGH RISK (70–89)**: Strong deception signatures; warning banners triggered.
* **DANGEROUS (90–100)**: Confirmed weaponized phishing or credential harvesting; immediate interception.

---

## Installation

### 1. Install Dependencies
```bash
npm install
```

### 2. Build the Extension
```bash
npm run build:extension
```
This compiles the core engine and generates extension icon assets in `/extension`.

### 3. Load into Google Chrome
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle switch in the upper-right corner.
3. Click the **Load unpacked** button.
4. Select the `extension/` directory from this repository.
5. PhishGuard is now installed and active in your browser.

---

## Development

Run the development server and test harness:
```bash
npm run dev
```

Run TypeScript compilation and static verification:
```bash
npm run lint
```

Build the companion application:
```bash
npm run build
```

---

## Testing

PhishGuard includes an automated 18-scenario behavioral test suite (`src/core/tests/testSuite.ts`) that verifies detection accuracy across realistic phishing simulations and legitimate baselines without contacting real malicious infrastructure:

* **Attacker Scenarios**: Brand impersonation on free cloud hosts (Vinted on Netlify, Jumia on Vercel), homoglyphs (`paypa1.com`, `amaz0n-security-alert.top`), Punycode IDN spoofs, bare IP authentication portals, payment card harvesters, 2FA/OTP interceptors, cross-origin credential harvesters, fake tech support scareware, shortener redirect chains, and high-risk executable downloads.
* **Legitimate Baselines**: Verified branded portals (official Vinted, GitHub, Stripe Checkout), documentation subdomains with query parameters, and static personal portfolios hosted on Netlify without forms (verifying zero false positives on benign cloud-hosted sites).

Run the automated test suite from the terminal:
```bash
npm test
```

---

## Project Structure

```text
phishguard/
├── extension/                   # Standalone Chrome Manifest V3 Extension
│   ├── manifest.json            # Manifest V3 specification
│   ├── background/
│   │   └── serviceWorker.js     # Background service worker & badge manager
│   ├── content/
│   │   └── contentScript.js     # Content script, DOM inspector & warning UI
│   ├── popup/                   # Browser action popup UI
│   ├── options/                 # Extension settings & allowlist configuration
│   ├── warning/                 # Full-page warning interstitial
│   ├── config/                  # Brand lists and rule weight configs
│   ├── engine/                  # Compiled client-side detection engine
│   └── icons/                   # Extension icons (16, 32, 48, 128px)
├── src/
│   ├── core/                    # Canonical TypeScript detection engine & test suite
│   │   ├── config/              # Rules, brand models, and heuristic thresholds
│   │   ├── engine/              # Typosquatting, URL, DOM form, and scoring modules
│   │   ├── tests/               # 18-scenario behavioral test suite
│   │   └── types.ts             # TypeScript interfaces and verdict definitions
│   ├── components/              # Development dashboard, test replayer & pipeline UI
│   └── server/                  # Optional local companion database & incident store
├── scripts/                     # Extension build, icon generation & packaging scripts
├── server.ts                    # Full-stack companion Express/Vite server
└── package.json                 # Project scripts and dependencies
```

---

## Technology

* **TypeScript 5.8** & **JavaScript (ES Modules)**
* **Google Chrome Manifest V3**
* **React 19** & **Tailwind CSS 4** (Development test harness UI)
* **Vite 6** & **esbuild** (Bundling and fast development server)
* **Express 4** (Optional companion development telemetry server)

---

## Security Considerations & Limitations

* **Sandbox Constraints**: Extension content scripts operate within Chrome's isolated world security model. Script-level mutations inside sandboxed third-party `<iframe>` elements with restricted permissions cannot be accessed due to browser security boundaries.
* **Zero-Day Heuristics**: Heuristic detection is probabilistic; while tuned against a curated dataset and protected brand registry, novel obfuscation methods may require iterative rule updates.
* **Local Scope**: The standalone extension does not make external threat intelligence lookups by default, preserving complete privacy at the trade-off of relying on client-side analysis.

---

## Contributing

Contributions, bug reports, and rule improvements are welcome! Please ensure that any PR modifying detection logic includes corresponding test cases in `src/core/tests/testSuite.ts` and that `npm test` and `npm run lint` pass cleanly before submitting.

---

## License

This project is licensed under the [MIT License](LICENSE).
