import { runSecurityTestSuite } from '../src/core/tests/testSuite';
import { runCloudDeploymentTestSuite } from '../src/core/tests/cloudDeploymentSuite';
import { runAuthLoginRegressionTests } from '../tests/auth-login-regression.test';

async function main() {
  // Ensure server-side session secret environment variable is present for tests
  if (!process.env.PHISHGUARD_SESSION_SECRET) {
    process.env.PHISHGUARD_SESSION_SECRET = 'pg_test_suite_secret_env_value_2026';
  }

  console.log('================================================================');
  console.log('🛡️  PHISHGUARD COMPREHENSIVE TEST SUITE EXECUTION');
  console.log('================================================================\n');

  console.log('--- 1. Running Deterministic Behavioral Detection Suite ---');
  const secResults = await runSecurityTestSuite();
  console.log(`Behavioral Tests: ${secResults.passed}/${secResults.total} passed (${secResults.passRate}%)\n`);

  console.log('--- 2. Running Cloud Deployment & Multi-Tenant Isolation Suite ---');
  const cloudResults = await runCloudDeploymentTestSuite();
  for (const r of cloudResults.results) {
    if (r.passed) {
      console.log(`  ✅ ${r.name} (${r.durationMs}ms)`);
    } else {
      console.error(`  ❌ ${r.name}: ${r.error}`);
    }
  }
  console.log(`Cloud Deployment Tests: ${cloudResults.passed}/${cloudResults.total} passed\n`);

  console.log('--- 3. Running Authentication & Super Admin Login Regression Suite ---');
  const authResults = await runAuthLoginRegressionTests();
  if (authResults.failed === 0) {
    console.log(`  ✅ All ${authResults.passed} Authentication Regression tests passed!\n`);
  } else {
    for (const err of authResults.errors) {
      console.error(`  ❌ ${err}`);
    }
    console.error(`Authentication Regression Tests: ${authResults.passed} passed, ${authResults.failed} failed\n`);
  }

  const totalTests = secResults.total + cloudResults.total + authResults.passed + authResults.failed;
  const totalPassed = secResults.passed + cloudResults.passed + authResults.passed;
  const totalFailed = secResults.failed + cloudResults.failed + authResults.failed;

  console.log('================================================================');
  console.log(`📊 TOTAL SUMMARY: ${totalPassed}/${totalTests} Passed (${totalFailed} Failed)`);
  console.log('================================================================');

  if (totalFailed > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
