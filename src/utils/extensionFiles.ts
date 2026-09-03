/// <reference types="vite/client" />
import JSZip from 'jszip';

export interface ExtensionFileDefinition {
  path: string;
  category: 'manifest' | 'background' | 'content' | 'ui' | 'engine' | 'config' | 'icons';
  description: string;
  getContent: () => string;
}

// Dynamically import all text files from the extension folder
const rawExtensionTextFiles: Record<string, string> = import.meta.glob(
  ['/extension/**/*', '!/extension/**/*.png'],
  { query: '?raw', import: 'default', eager: true }
);

function getCategoryForPath(path: string): string {
  if (path.includes('manifest.json')) return 'manifest';
  if (path.includes('background/')) return 'background';
  if (path.includes('content/')) return 'content';
  if (path.includes('engine/')) return 'engine';
  if (path.includes('config/')) return 'config';
  if (path.includes('icons/')) return 'icons';
  return 'ui';
}

function getDescriptionForPath(path: string): string {
  if (path.includes('manifest.json')) return 'Chrome Manifest V3 declaration, permissions, and service worker registration';
  if (path.includes('serviceWorker.js')) return 'Background service worker coordinating tab scanning, badges, and interstitials';
  if (path.includes('contentScript.js')) return 'Content script inspecting DOM form and input structures with zero credential logging';
  if (path.includes('riskScoring.js')) return 'Compiled multi-heuristic risk orchestrator & compound threat scoring engine';
  if (path.includes('urlAnalysis.js')) return 'Compiled URL entropy, IP format, punycode IDN, and keyword parser';
  if (path.includes('typosquatting.js')) return 'Compiled Damerau-Levenshtein & visual homoglyph detector';
  if (path.includes('formAnalysis.js')) return 'Compiled credential harvesting and cross-origin drop point evaluator';
  if (path.includes('redirectAnalysis.js')) return 'Compiled multi-hop trampoline & URL shortener evaluator';
  if (path.includes('reputation.js')) return 'Compiled local allowlist and fast blocklist matcher';
  if (path.includes('rules.js')) return 'Compiled heuristic thresholds and suspicious keyword tables';
  if (path.includes('brands.js')) return 'Compiled protected brand database & canonical domain catalogs';
  if (path.includes('popup.html') || path.includes('popup.js') || path.includes('popup.css')) return 'Extension toolbar action popup UI';
  if (path.includes('options.html') || path.includes('options.js') || path.includes('options.css')) return 'Extension options & custom list management UI';
  if (path.includes('warning.html') || path.includes('warning.js') || path.includes('warning.css')) return 'Full-page warning interstitial for blocked phishing destinations';
  return 'Chrome extension source file';
}

export const EXTENSION_FILES: Record<string, { category: string; description: string; content: string }> = (() => {
  const result: Record<string, { category: string; description: string; content: string }> = {};

  for (const [fullPath, content] of Object.entries(rawExtensionTextFiles)) {
    const cleanPath = fullPath
      .replace(/^(\.\.\/|\.\/|\/)*extension\//, '')
      .replace(/^\/+/, '');
    
    result[cleanPath] = {
      category: getCategoryForPath(cleanPath),
      description: getDescriptionForPath(cleanPath),
      content: typeof content === 'string' ? content : String(content)
    };
  }

  return result;
})();

export function getExtensionFilesList(): ExtensionFileDefinition[] {
  return Object.entries(EXTENSION_FILES).map(([path, data]) => ({
    path,
    category: data.category as ExtensionFileDefinition['category'],
    description: data.description,
    getContent: () => data.content
  }));
}

/**
 * Generates ready-to-load Chrome Manifest V3 ZIP blob
 */
export async function generateExtensionZipBlob(): Promise<Blob> {
  const zip = new JSZip();

  // Add all extension text files
  for (const [filePath, data] of Object.entries(EXTENSION_FILES)) {
    zip.file(filePath, data.content);
  }

  // Add README
  zip.file(
    'README.md',
    `# PhishGuard — Chrome Extension (Manifest V3)

## How to Install Unpacked in Google Chrome:

1. Extract this entire zip file into a folder on your computer (e.g., \`phishguard-extension/\`).
2. Open Google Chrome and navigate to \`chrome://extensions/\`.
3. Enable the **"Developer mode"** toggle in the top-right corner.
4. Click the **"Load unpacked"** button in the top-left.
5. Select the extracted folder containing \`manifest.json\`.
6. PhishGuard is now active in your browser!

### Verification & Testing:
- Visit any website (e.g. \`https://www.google.com\`) and click the PhishGuard toolbar icon.
- Test suspicious URLs (such as \`https://www.paypa1.com\`) to observe heuristic warnings and risk scores.
- Access Settings via the extension popup to manage allowlists, blocklists, and detection sensitivity.
`
  );

  // Generate binary PNG icons in ZIP via Canvas API if available
  const iconSizes = [16, 32, 48, 128];
  for (const size of iconSizes) {
    try {
      if (typeof document !== 'undefined') {
        const canvas = document.createElement('canvas');
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext('2d');
        if (ctx) {
          ctx.fillStyle = '#4F46E5';
          ctx.beginPath();
          ctx.moveTo(size * 0.5, size * 0.1);
          ctx.lineTo(size * 0.85, size * 0.25);
          ctx.lineTo(size * 0.85, size * 0.6);
          ctx.bezierCurveTo(size * 0.85, size * 0.85, size * 0.5, size * 0.95, size * 0.5, size * 0.95);
          ctx.bezierCurveTo(size * 0.5, size * 0.95, size * 0.15, size * 0.85, size * 0.15, size * 0.6);
          ctx.lineTo(size * 0.15, size * 0.25);
          ctx.closePath();
          ctx.fill();

          ctx.strokeStyle = '#FFFFFF';
          ctx.lineWidth = Math.max(1.5, size * 0.08);
          ctx.beginPath();
          ctx.moveTo(size * 0.35, size * 0.5);
          ctx.lineTo(size * 0.47, size * 0.65);
          ctx.lineTo(size * 0.68, size * 0.38);
          ctx.stroke();

          const base64Data = canvas.toDataURL('image/png').split(',')[1];
          zip.file(`icons/icon${size}.png`, base64Data, { base64: true });
        }
      }
    } catch {
      // Ignore if canvas not available
    }
  }

  return await zip.generateAsync({ type: 'blob' });
}

/**
 * Initiates download of the extension zip in the browser
 */
export async function downloadExtensionZip(): Promise<void> {
  const blob = await generateExtensionZipBlob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'phishguard-chrome-extension-v3.zip';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
