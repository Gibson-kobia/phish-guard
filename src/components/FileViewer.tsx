import React, { useState } from 'react';
import { 
  FileText, Folder, Check, Copy, Download, 
  Terminal, ShieldCheck, ExternalLink, RefreshCw 
} from 'lucide-react';
import { EXTENSION_FILES, generateExtensionZipBlob } from '../utils/extensionFiles';

export const FileViewer: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<string>('manifest.json');
  const [copied, setCopied] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const fileEntries = Object.entries(EXTENSION_FILES);

  const handleCopy = () => {
    const content = EXTENSION_FILES[selectedFile]?.content || '';
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleDownloadZip = async () => {
    try {
      setDownloading(true);
      const blob = await generateExtensionZipBlob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'phishguard-extension-v3.zip';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to generate extension zip:', err);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Installation Instructions Header */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <h2 className="text-base font-bold text-white">
                Chrome Extension (Manifest V3) Package
              </h2>
            </div>
            <p className="text-xs text-slate-400">
              Complete, production-ready extension package ready to load directly into Google Chrome, Microsoft Edge, or Brave.
            </p>
          </div>

          <button
            onClick={handleDownloadZip}
            disabled={downloading}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white shadow-md shadow-emerald-700/20 transition-all cursor-pointer whitespace-nowrap"
          >
            {downloading ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Download className="w-4 h-4" />
            )}
            <span>Download All Extension Files (.ZIP)</span>
          </button>
        </div>

        {/* Step-by-Step Installation Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-slate-800 text-xs">
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="text-blue-400 font-bold block font-mono">STEP 1</span>
            <span className="font-semibold text-slate-200 block">Download &amp; Unzip</span>
            <p className="text-[11px] text-slate-400">Extract the downloaded ZIP archive into any local folder.</p>
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="text-blue-400 font-bold block font-mono">STEP 2</span>
            <span className="font-semibold text-slate-200 block">Open Extensions</span>
            <p className="text-[11px] text-slate-400">Navigate to <code className="text-blue-300">chrome://extensions/</code> in Chrome.</p>
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="text-blue-400 font-bold block font-mono">STEP 3</span>
            <span className="font-semibold text-slate-200 block">Enable Dev Mode</span>
            <p className="text-[11px] text-slate-400">Toggle &quot;Developer mode&quot; in the top-right corner.</p>
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
            <span className="text-emerald-400 font-bold block font-mono">STEP 4</span>
            <span className="font-semibold text-slate-200 block">Load Unpacked</span>
            <p className="text-[11px] text-slate-400">Click &quot;Load unpacked&quot; and select the unzipped directory.</p>
          </div>
        </div>
      </div>

      {/* File Tree & Code Viewer */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden min-h-[500px]">
        {/* Left Sidebar: File Navigator */}
        <div className="md:col-span-4 border-b md:border-b-0 md:border-r border-slate-800 bg-slate-950 p-4 space-y-2">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Extension Files ({fileEntries.length})
            </span>
            <span className="text-[10px] font-mono text-emerald-400">Manifest V3</span>
          </div>

          <div className="space-y-1">
            {fileEntries.map(([filename, info]) => (
              <button
                key={filename}
                onClick={() => setSelectedFile(filename)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono text-left transition-all cursor-pointer ${
                  selectedFile === filename
                    ? 'bg-blue-600/20 text-blue-300 border border-blue-500/30'
                    : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                }`}
              >
                <div className="flex items-center gap-2 truncate">
                  <FileText className="w-3.5 h-3.5 shrink-0 text-slate-500" />
                  <span className="truncate">{filename}</span>
                </div>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 text-slate-500 uppercase">
                  {info.category}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Right Area: Code Display */}
        <div className="md:col-span-8 p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <span className="text-xs font-bold font-mono text-white block">
                  /{selectedFile}
                </span>
                <span className="text-[11px] text-slate-400">
                  {EXTENSION_FILES[selectedFile]?.description}
                </span>
              </div>

              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied!' : 'Copy Code'}</span>
              </button>
            </div>

            <pre className="mt-4 p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-[460px] leading-relaxed scrollbar-thin">
              {EXTENSION_FILES[selectedFile]?.content}
            </pre>
          </div>

          <div className="text-[11px] text-slate-500 flex justify-between items-center pt-2 border-t border-slate-800/80">
            <span>Standard WebExtensions API &amp; Chrome Manifest V3 specifications</span>
            <span>Zero external cloud dependencies</span>
          </div>
        </div>
      </div>
    </div>
  );
};
