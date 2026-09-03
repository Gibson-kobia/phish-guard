import * as esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';

async function buildExtension() {
  console.log('📦 Compiling PhishGuard Detection Engine for Chrome Extension...');

  const configDir = path.resolve('extension/config');
  const engineDir = path.resolve('extension/engine');
  const eventsDir = path.resolve('extension/events');
  const loggingDir = path.resolve('extension/logging');

  fs.mkdirSync(configDir, { recursive: true });
  fs.mkdirSync(engineDir, { recursive: true });
  fs.mkdirSync(eventsDir, { recursive: true });
  fs.mkdirSync(loggingDir, { recursive: true });

  // Core files to transpile from canonical src/core/ source of truth
  const files = [
    { in: 'src/core/config/brands.ts', out: 'extension/config/brands.js' },
    { in: 'src/core/config/rules.ts', out: 'extension/config/rules.js' },
    { in: 'src/core/config/trustedProviders.ts', out: 'extension/config/trustedProviders.js' },
    { in: 'src/core/engine/brandIdentity.ts', out: 'extension/engine/brandIdentity.js' },
    { in: 'src/core/engine/urlAnalysis.ts', out: 'extension/engine/urlAnalysis.js' },
    { in: 'src/core/engine/typosquatting.ts', out: 'extension/engine/typosquatting.js' },
    { in: 'src/core/engine/formAnalysis.ts', out: 'extension/engine/formAnalysis.js' },
    { in: 'src/core/engine/socialEngineering.ts', out: 'extension/engine/socialEngineering.js' },
    { in: 'src/core/engine/downloads.ts', out: 'extension/engine/downloads.js' },
    { in: 'src/core/engine/redirectAnalysis.ts', out: 'extension/engine/redirectAnalysis.js' },
    { in: 'src/core/engine/reputation.ts', out: 'extension/engine/reputation.js' },
    { in: 'src/core/engine/timeline.ts', out: 'extension/engine/timeline.js' },
    { in: 'src/core/engine/riskScoring.ts', out: 'extension/engine/riskScoring.js' },
    { in: 'src/core/engine/intelligenceLayer.ts', out: 'extension/engine/intelligenceLayer.js' },
    { in: 'src/core/engine/threatIntelligence.ts', out: 'extension/engine/threatIntelligence.js' },
    { in: 'src/core/logging/securityLogger.ts', out: 'extension/logging/securityLogger.js' },
    { in: 'src/core/events/eventStore.ts', out: 'extension/events/eventStore.js' },
    { in: 'src/core/events/networkEvents.ts', out: 'extension/events/networkEvents.js' },
    { in: 'src/core/events/pageEvents.ts', out: 'extension/events/pageEvents.js' },
    { in: 'src/core/events/formEvents.ts', out: 'extension/events/formEvents.js' },
    { in: 'src/core/events/navigationEvents.ts', out: 'extension/events/navigationEvents.js' },
    { in: 'src/core/events/downloadEvents.ts', out: 'extension/events/downloadEvents.js' },
    { in: 'src/core/events/eventCorrelator.ts', out: 'extension/events/eventCorrelator.js' },
    { in: 'src/core/events/canonicalEvent.ts', out: 'extension/events/canonicalEvent.js' },
    { in: 'src/core/events/durableQueue.ts', out: 'extension/events/durableQueue.js' },
  ];

  for (const f of files) {
    if (!fs.existsSync(f.in)) {
      console.warn(`Skipping missing source file: ${f.in}`);
      continue;
    }

    await esbuild.build({
      entryPoints: [f.in],
      outfile: f.out,
      format: 'esm',
      target: 'es2022',
      platform: 'browser',
      bundle: false,
      minify: false,
      sourcemap: false
    });

    // Fix relative import extensions to .js for native Chrome ES module loader
    let content = fs.readFileSync(f.out, 'utf-8');
    content = content.replace(/from\s+['"](\.\.?\/[^'"]+)['"]/g, (match, p1) => {
      // Remove any trailing ../types references since types are stripped by esbuild
      if (p1.includes('types')) {
        return match;
      }
      if (!p1.endsWith('.js')) {
        return `from '${p1}.js'`;
      }
      return match;
    });
    // Remove type-only imports that may leave empty imports
    content = content.replace(/import\s*\{\s*\}\s*from\s*['"][^'"]+['"];?\n?/g, '');
    fs.writeFileSync(f.out, content);
  }

  // Validate manifest.json exists and is valid JSON
  const manifestPath = path.resolve('extension/manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error('extension/manifest.json is missing!');
  }
  const manifestContent = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
  if (!manifestContent.name || !manifestContent.version || manifestContent.manifest_version !== 3) {
    throw new Error('extension/manifest.json is invalid Manifest V3!');
  }

  console.log(`✅ Chrome Extension engine successfully built from src/core/ (Manifest v${manifestContent.version})!`);
}

buildExtension().catch((err) => {
  console.error('❌ Failed to compile extension:', err);
  process.exit(1);
});
