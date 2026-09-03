import fs from 'fs';
import path from 'path';
import JSZip from 'jszip';

interface ManifestSchema {
  manifest_version: number;
  name: string;
  version: string;
  description?: string;
  icons?: Record<string, string>;
  action?: {
    default_popup?: string;
    default_icon?: Record<string, string>;
  };
  background?: {
    service_worker?: string;
    type?: string;
  };
  content_scripts?: Array<{
    matches: string[];
    js?: string[];
    css?: string[];
  }>;
  options_ui?: {
    page?: string;
  };
  web_accessible_resources?: Array<{
    resources: string[];
    matches: string[];
  }>;
}

/**
 * Normalizes all path separators to standard forward slashes for ZIP & Chrome compatibility
 */
function normalizeZipPath(filePath: string): string {
  return filePath.replace(/\\/g, '/').replace(/^\/+/, '');
}

/**
 * Copies directory recursively
 */
function copyDirRecursive(sourceDir: string, destDir: string) {
  fs.mkdirSync(destDir, { recursive: true });
  const entries = fs.readdirSync(sourceDir, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(sourceDir, entry.name);
    const destPath = path.join(destDir, entry.name);

    if (entry.isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else if (entry.isFile()) {
      if (entry.name === '.DS_Store' || entry.name.endsWith('.tmp') || entry.name.endsWith('.map')) {
        continue;
      }
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

async function packageExtension() {
  console.log('====================================================');
  console.log('📦 PHISHGUARD CHROME EXTENSION PACKAGING PIPELINE');
  console.log('====================================================');

  const rootDir = process.cwd();
  const extensionSourceDir = path.resolve(rootDir, 'extension');
  const distExtensionDir = path.resolve(rootDir, 'dist-extension');
  const stagingDir = path.resolve(distExtensionDir, 'staging');
  const testPackageDir = path.resolve(rootDir, 'phishguard-extension-test');

  // 1. Clean previous staging and output files
  console.log('\n[1/7] Cleaning previous packaging outputs...');
  if (fs.existsSync(stagingDir)) {
    fs.rmSync(stagingDir, { recursive: true, force: true });
  }
  if (fs.existsSync(testPackageDir)) {
    fs.rmSync(testPackageDir, { recursive: true, force: true });
  }

  // Remove previous zip archives
  const rootZips = fs.readdirSync(rootDir).filter(f => f.startsWith('phishguard-extension') && f.endsWith('.zip'));
  for (const zipFile of rootZips) {
    fs.unlinkSync(path.resolve(rootDir, zipFile));
    console.log(`  - Deleted previous zip: ${zipFile}`);
  }

  // 2. Prepare staging directory
  console.log('\n[2/7] Staging production extension files...');
  fs.mkdirSync(stagingDir, { recursive: true });
  copyDirRecursive(extensionSourceDir, stagingDir);

  // 3. Create phishguard-extension-test local unpack directory
  console.log('\n[3/7] Creating test package directory (phishguard-extension-test)...');
  copyDirRecursive(stagingDir, testPackageDir);

  // 4. Validate manifest.json inside staging
  console.log('\n[4/7] Validating manifest.json and referenced resources...');
  const manifestPath = path.join(stagingDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error('FATAL: manifest.json is missing at the root of the package staging directory!');
  }

  const manifestRaw = fs.readFileSync(manifestPath, 'utf-8');
  let manifest: ManifestSchema;
  try {
    manifest = JSON.parse(manifestRaw);
  } catch (err) {
    throw new Error(`FATAL: manifest.json is corrupted or unparseable JSON: ${String(err)}`);
  }

  if (manifest.manifest_version !== 3) {
    throw new Error(`FATAL: Expected manifest_version 3, got ${manifest.manifest_version}`);
  }

  // Check all manifest-declared resources
  const requiredFiles: string[] = ['manifest.json'];

  if (manifest.background?.service_worker) {
    requiredFiles.push(manifest.background.service_worker);
  }
  if (manifest.action?.default_popup) {
    requiredFiles.push(manifest.action.default_popup);
  }
  if (manifest.options_ui?.page) {
    requiredFiles.push(manifest.options_ui.page);
  }
  if (manifest.icons) {
    Object.values(manifest.icons).forEach(iconPath => requiredFiles.push(iconPath));
  }
  if (manifest.action?.default_icon) {
    Object.values(manifest.action.default_icon).forEach(iconPath => requiredFiles.push(iconPath));
  }
  if (manifest.content_scripts) {
    for (const cs of manifest.content_scripts) {
      if (cs.js) cs.js.forEach(p => requiredFiles.push(p));
      if (cs.css) cs.css.forEach(p => requiredFiles.push(p));
    }
  }

  console.log('  Verifying required manifest dependencies:');
  for (const relPath of requiredFiles) {
    const cleanRel = normalizeZipPath(relPath);
    const absPath = path.join(stagingDir, cleanRel);
    if (!fs.existsSync(absPath)) {
      throw new Error(`FATAL: Manifest-referenced file not found in package: "${cleanRel}" (looking at ${absPath})`);
    }
    console.log(`    ✓ ${cleanRel.padEnd(32)} EXISTS (${fs.statSync(absPath).size} bytes)`);
  }

  // 5. Build ZIP file with manifest.json explicitly at ROOT
  console.log('\n[5/7] Assembling ZIP archive with root manifest...');
  const zip = new JSZip();

  // Recursively collect all files from staging
  function addStagingToZip(currentDir: string, relativePrefix: string = '') {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const entryRelPath = relativePrefix ? `${relativePrefix}/${entry.name}` : entry.name;
      const normalizedPath = normalizeZipPath(entryRelPath);

      if (entry.isDirectory()) {
        addStagingToZip(fullPath, normalizedPath);
      } else if (entry.isFile()) {
        const fileContent = fs.readFileSync(fullPath);
        // Explicitly set forward slash path and DOS compatibility for Windows / Chrome
        zip.file(normalizedPath, fileContent, {
          createFolders: true,
          date: new Date()
        });
      }
    }
  }

  addStagingToZip(stagingDir);

  const zipVersion = manifest.version || '1.0.0';
  const zipFilename = `phishguard-extension-v${zipVersion}.zip`;
  const distZipPath = path.join(distExtensionDir, zipFilename);
  const rootZipPath = path.join(rootDir, zipFilename);

  const zipBuffer = await zip.generateAsync({
    type: 'nodebuffer',
    compression: 'DEFLATE',
    compressionOptions: { level: 9 },
    platform: 'UNIX'
  });

  fs.writeFileSync(distZipPath, zipBuffer);
  fs.writeFileSync(rootZipPath, zipBuffer);

  // 6. Programmatically verify generated ZIP archive
  console.log('\n[6/7] Programmatically verifying generated ZIP contents...');
  const verifyZip = await JSZip.loadAsync(zipBuffer);
  const zipEntries = Object.keys(verifyZip.files);

  console.log(`  Total files in ZIP: ${zipEntries.length}`);
  console.log('  ZIP entry structure:');
  for (const entry of zipEntries) {
    const isDir = verifyZip.files[entry].dir;
    console.log(`    ${isDir ? '📁' : '📄'} ${entry}`);
  }

  // Confirm manifest.json is at the immediate root of the ZIP
  if (!verifyZip.files['manifest.json'] || verifyZip.files['manifest.json'].dir) {
    throw new Error('FATAL VERIFICATION ERROR: "manifest.json" is not directly at the root of the generated ZIP archive!');
  }

  const packagedManifestRaw = await verifyZip.files['manifest.json'].async('string');
  const packagedManifest = JSON.parse(packagedManifestRaw);
  if (packagedManifest.name !== manifest.name || packagedManifest.version !== manifest.version) {
    throw new Error('FATAL VERIFICATION ERROR: Packaged manifest.json content mismatch!');
  }

  // 7. Summary
  const zipSizeKb = (zipBuffer.length / 1024).toFixed(1);
  console.log('\n[7/7] Packaging Complete!');
  console.log('====================================================');
  console.log(`PACKAGE ROOT (Test Directory):`);
  console.log(`  ${testPackageDir}`);
  console.log(`\nZIP ARCHIVE:`);
  console.log(`  ${rootZipPath} (${zipSizeKb} KB)`);
  console.log(`\nREADY FOR CHROME:`);
  console.log(`  1. Open chrome://extensions`);
  console.log(`  2. Enable "Developer mode"`);
  console.log(`  3. Click "Load unpacked"`);
  console.log(`  4. Select: ${testPackageDir}`);
  console.log('====================================================\n');
}

packageExtension().catch(err => {
  console.error('\n❌ Packaging Failed:', err);
  process.exit(1);
});

