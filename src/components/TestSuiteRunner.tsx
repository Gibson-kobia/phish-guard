import React, { useState } from 'react';
import { 
  Play, CheckCircle2, XCircle, Clock, ShieldCheck, 
  AlertOctagon, Filter, RefreshCw, Layers, Shield
} from 'lucide-react';
import { SECURITY_TEST_CASES, runSecurityTestSuite, TestRunResult } from '../core/tests/testSuite';

export const TestSuiteRunner: React.FC = () => {
  const [running, setRunning] = useState(false);
  const [testResults, setTestResults] = useState<{
    total: number;
    passed: number;
    failed: number;
    passRate: number;
    totalTimeMs: number;
    results: TestRunResult[];
  } | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('ALL');

  const handleRunTests = async () => {
    setRunning(true);
    setTimeout(async () => {
      const outcome = await runSecurityTestSuite();
      setTestResults(outcome);
      setRunning(false);
    }, 50);
  };

  const categories = [
    'ALL', 
    'SAFE', 
    'FALSE_POSITIVE_CHECK', 
    'TYPOSQUATTING', 
    'COMBOSQUATTING',
    'IP_URL', 
    'DOM_CROSS_ORIGIN', 
    'PUNYCODE', 
    'REDIRECT', 
    'SOCIAL_ENGINEERING',
    'DOWNLOAD_SECURITY',
    'KNOWN_BLOCKLIST'
  ];

  const displayedResults = testResults?.results.filter(r => {
    if (filterCategory === 'ALL') return true;
    return r.category === filterCategory;
  }) || [];

  return (
    <div className="space-y-6">
      {/* Top Banner with Stats & Execution trigger */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <ShieldCheck className="w-5 h-5 text-blue-400" />
              <h2 className="text-base font-bold text-white">Security Validation Benchmark Suite</h2>
            </div>
            <p className="text-xs text-slate-400">
              Validates deterministic heuristic accuracy, false-positive protection, homoglyphs, coercive language, and downloads across {SECURITY_TEST_CASES.length} standardized test scenarios.
            </p>
          </div>

          <button
            id="btn-run-tests"
            onClick={handleRunTests}
            disabled={running}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/20 transition-all cursor-pointer whitespace-nowrap"
          >
            {running ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4 fill-white" />
            )}
            <span>{running ? 'Executing Tests...' : 'Run Test Suite'}</span>
          </button>
        </div>

        {/* Metrics Overview */}
        {testResults && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-slate-800">
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400 block font-medium">Pass Rate</span>
              <span className={`text-2xl font-black font-mono ${
                testResults.passRate === 100 ? 'text-emerald-400' : 'text-amber-400'
              }`}>
                {testResults.passRate}%
              </span>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400 block font-medium">Tests Passed</span>
              <span className="text-2xl font-black font-mono text-emerald-400">
                {testResults.passed} <span className="text-xs text-slate-500 font-normal">/ {testResults.total}</span>
              </span>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400 block font-medium">Tests Failed</span>
              <span className={`text-2xl font-black font-mono ${
                testResults.failed === 0 ? 'text-slate-500' : 'text-red-400'
              }`}>
                {testResults.failed}
              </span>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-[11px] text-slate-400 block font-medium">Latency Benchmark</span>
              <span className="text-2xl font-black font-mono text-blue-400">
                {testResults.totalTimeMs}ms
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Category Filter bar */}
      {testResults && (
        <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin">
          <Filter className="w-4 h-4 text-slate-400 shrink-0" />
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setFilterCategory(cat)}
              className={`px-2.5 py-1 rounded-md text-xs font-mono transition-colors whitespace-nowrap cursor-pointer ${
                filterCategory === cat
                  ? 'bg-blue-600 text-white font-bold'
                  : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
      )}

      {/* Results Table / List */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
        {!testResults ? (
          <div className="p-12 text-center space-y-3">
            <Layers className="w-10 h-10 text-slate-600 mx-auto" />
            <h3 className="text-sm font-semibold text-slate-300">Test Suite Idle</h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Click &quot;Run Test Suite&quot; above to execute automated validation against phishing homoglyphs, combosquatting, social engineering lures, and false-positive baseline scenarios.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {displayedResults.map((result, idx) => (
              <div key={idx} className="p-4 hover:bg-slate-800/30 transition-colors space-y-2">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    {result.passed ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-200">{result.testName}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono">
                          {result.category}
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-slate-400 block mt-0.5">
                        {result.analysis.url}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-right">
                      <span className={`text-xs font-bold font-mono ${
                        result.actualVerdict === 'DANGEROUS' ? 'text-red-500' :
                        result.actualVerdict === 'HIGH_RISK' ? 'text-red-400' :
                        result.actualVerdict === 'SUSPICIOUS' ? 'text-amber-400' :
                        result.actualVerdict === 'LOW_RISK' ? 'text-blue-400' : 'text-emerald-400'
                      }`}>
                        {result.actualVerdict} ({result.actualScore}/100)
                      </span>
                      <span className="text-[10px] text-slate-500 block">
                        Target: {result.expectedVerdict}
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-400 bg-slate-950 px-2 py-1 rounded border border-slate-800">
                      {result.executionTimeMs}ms
                    </span>
                  </div>
                </div>

                {/* Signals found preview */}
                {result.signalsFound.length > 0 && (
                  <div className="pl-6.5 flex flex-wrap gap-1.5 pt-1">
                    {result.signalsFound.map((sig, sIdx) => (
                      <span key={sIdx} className="text-[10px] px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                        {sig}
                      </span>
                    ))}
                  </div>
                )}

                {/* Failure explanation */}
                {result.failureReason && (
                  <div className="pl-6.5 text-xs text-red-400 font-mono bg-red-950/20 p-2 rounded border border-red-900/40">
                    Failure: {result.failureReason}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
