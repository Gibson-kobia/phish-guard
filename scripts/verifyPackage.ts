import fs from 'fs';
import path from 'path';
import JSZip from 'jszip';

async function verifyPackage() {
  console.log('====================================================');
  console.log('🔍 INDEPENDENT PACKAGING & MANIFEST AUDIT');
  console.log('====================================================');

  const rootDir = process.cwd();
  const testDir = path.join(rootDir, 'phishguard-extension-test');
  const zipPath = path.join(rootDir, 'phishguard-extension-v1.0.0.zip');

  // 1. Check phishguard-extension-test directory
  console.log('\n[1] AUDITING TEST DIRECTORY: phishguard-extension-test');
  console.log(`Directory: ${testDir}`);
  if (!fs.existsSync(testDir)) {
    throw new Error('phishguard-extension-test directory does not exist!');
  }

  const manifestPath = path.join(testDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error('manifest.json is NOT directly at the root of phishguard-extension-test!');
  }
  console.log('  ✓ manifest.json exists directly at directory root');

  const manifestRaw = fs.readFileSync(manifestPath, 'utf-8');
  let manifest;
  try {
    manifest = JSON.parse(manifestRaw);
    console.log(`  ✓ manifest.json is valid JSON (version: ${manifest.version}, manifest_version: ${manifest.manifest_version})`);
  } catch (err) {
    throw new Error(`manifest.json is invalid JSON: ${err}`);
  }

  // Check manifest files
  const requiredFiles = [
    'manifest.json',
    manifest.background?.service_worker,
    manifest.action?.default_popup,
    manifest.options_ui?.page,
    ...(manifest.icons ? Object.values(manifest.icons) : []),
    ...(manifest.content_scripts ? manifest.content_scripts.flatMap((cs: { js?: string[] }) => cs.js || []) : [])
  ].filter(Boolean);

  console.log('\n[2] VERIFYING MANIFEST-REFERENCED FILES IN TEST DIRECTORY:');
  for (const relPath of requiredFiles) {
    const fullPath = path.join(testDir, relPath as string);
    if (!fs.existsSync(fullPath)) {
      throw new Error(`MISSING FILE: ${relPath} does not exist in phishguard-extension-test!`);
    }
    const stats = fs.statSync(fullPath);
    console.log(`  ${(relPath as string).padEnd(36)} EXISTS (${stats.size} bytes)`);
  }

  // Check engine and config files in testDir
  const expectedEngineFiles = [
    'config/brands.js',
    'config/rules.js',
    'config/trustedProviders.js',
    'engine/brandIdentity.js',
    'engine/downloads.js',
    'engine/formAnalysis.js',
    'engine/intelligenceLayer.js',
    'engine/redirectAnalysis.js',
    'engine/reputation.js',
    'engine/riskScoring.js',
    'engine/socialEngineering.js',
    'engine/timeline.js',
    'engine/typosquatting.js',
    'engine/urlAnalysis.js',
    'events/eventStore.js',
    'events/eventCorrelator.js',
    'events/networkEvents.js',
    'events/pageEvents.js',
    'events/formEvents.js',
    'events/navigationEvents.js',
    'events/downloadEvents.js',
    'warning/warning.html',
    'warning/warning.js',
    'warning/warning.css',
    'popup/popup.html',
    'popup/popup.js',
    'popup/popup.css',
    'options/options.html',
    'options/options.js',
    'options/options.css'
  ];

  console.log('\n[3] VERIFYING RUNTIME MODULES IN TEST DIRECTORY:');
  for (const relPath of expectedEngineFiles) {
    const fullPath = path.join(testDir, relPath);
    if (!fs.existsSync(fullPath)) {
      throw new Error(`MISSING RUNTIME MODULE: ${relPath} in phishguard-extension-test!`);
    }
    const stats = fs.statSync(fullPath);
    console.log(`  ${relPath.padEnd(36)} EXISTS (${stats.size} bytes)`);
  }

  // 4. Audit the ZIP file directly
  console.log('\n[4] AUDITING ZIP ARCHIVE');
  console.log(`ZIP: ${zipPath}`);
  if (!fs.existsSync(zipPath)) {
    throw new Error(`ZIP file ${zipPath} does not exist!`);
  }
  const zipStats = fs.statSync(zipPath);
  console.log(`ZIP SIZE: ${(zipStats.size / 1024).toFixed(1)} KB (${zipStats.size} bytes)`);

  const zipBuffer = fs.readFileSync(zipPath);
  const zip = await JSZip.loadAsync(zipBuffer);
  const zipEntries = Object.keys(zip.files).sort();

  console.log('\n[5] COMPLETE ZIP FILE LIST (ROOT-LEVEL AUDIT):');
  let hasRootManifest = false;
  for (const entry of zipEntries) {
    const isDir = zip.files[entry].dir;
    if (entry === 'manifest.json' && !isDir) {
      hasRootManifest = true;
    }
    // Check if path uses any backslashes
    if (entry.includes('\\')) {
      throw new Error(`INVALID ZIP ENTRY (contains backslash): ${entry}`);
    }
    // Check if there is an unwanted root folder prefix
    if (entry.startsWith('phishguard-extension/') || entry.startsWith('extension/') || entry.startsWith('dist/')) {
      throw new Error(`UNWANTED NESTED ROOT IN ZIP: ${entry}`);
    }
    console.log(`  ${(isDir ? '📁 [DIR]' : '📄 [FILE]').padEnd(10)} ${entry}`);
  }

  if (!hasRootManifest) {
    throw new Error('FAIL: manifest.json is NOT at the immediate root level of the ZIP archive!');
  }
  console.log('\n✓ VERIFIED: manifest.json is directly at the first level / root of the ZIP file.');

  // Validate ZIP manifest content
  const zipManifestRaw = await zip.files['manifest.json'].async('string');
  const zipManifest = JSON.parse(zipManifestRaw);
  if (zipManifest.name !== manifest.name || zipManifest.version !== manifest.version) {
    throw new Error('FAIL: Packaged manifest.json in ZIP does not match source manifest.json!');
  }
  console.log('✓ VERIFIED: Packaged manifest.json in ZIP is valid and matches.');

  console.log('\n====================================================');
  console.log('🎉 AUDIT PASSED: ALL 5 CHECKS VERIFIED SUCCESSFULLY!');
  console.log('====================================================\n');
}

verifyPackage().catch(err => {
  console.error('\n❌ AUDIT FAILED:', err);
  process.exit(1);
});
