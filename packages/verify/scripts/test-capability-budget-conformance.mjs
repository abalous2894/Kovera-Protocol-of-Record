#!/usr/bin/env node
/**
 * CAP Phase 1 — capability budget attenuation conformance.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const verifyPkg = join(__dirname, '..');

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

console.log('\nCAP Phase 1 — capability budget conformance\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const {
  evaluateCapabilityBudget,
  deriveCapabilityBudgetFromSteps,
  buildCapabilityBudgetCommitment,
  verifyCapabilityBudgetCommitment,
  verifyBudgetMonotonicityFromPartialSteps,
  initialCapabilityBudget,
} = await import('@aevesa/verify');

ok('initial budget all sinks open', initialCapabilityBudget().external_network === true);

const laundering = evaluateCapabilityBudget(
  [{ toolName: 'read_file', verdict: 'ALLOW', pathHint: '/vault/confidential/payroll.csv' }],
  'send_email',
);
ok('blocks confidential read then email', laundering.allow === false);
ok('laundering code', laundering.code === 'CAPABILITY_BUDGET_EXHAUSTED');

const benign = evaluateCapabilityBudget(
  [{ toolName: 'list_dir', verdict: 'ALLOW' }],
  'read_file',
  { pathHint: '/tmp/public' },
);
ok('benign path allows read', benign.allow === true);

const commitment = buildCapabilityBudgetCommitment(laundering.budget, laundering.taintClass);
ok('budget commitment hash', verifyCapabilityBudgetCommitment(commitment).ok === true);

const partialSteps = [
  { index: 0, tool_name: 'read_file', verdict: 'allow', entry_hash: 'a'.repeat(64) },
  { index: 1, tool_name: 'grep_search', verdict: 'allow', entry_hash: 'b'.repeat(64) },
  { index: 2, tool_name: 'send_email', verdict: 'deny', entry_hash: 'c'.repeat(64) },
];
const mono = verifyBudgetMonotonicityFromPartialSteps(partialSteps);
ok('monotonic partial steps', mono.ok === true);

const derived = deriveCapabilityBudgetFromSteps([
  { toolName: 'read_file', verdict: 'ALLOW', pathHint: '/confidential/x' },
]);
ok('derive after confidential read closes email', derived.budget.email === false);

console.log(`\nCapability budget conformance: ${passed} checks passed.\n`);
