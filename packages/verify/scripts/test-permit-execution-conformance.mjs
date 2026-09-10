#!/usr/bin/env node
/**
 * CAP Phase 2 — permit–execution binding + manifest custodian conformance.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const verifyPkg = join(__dirname, '..');
const repoRoot = join(verifyPkg, '../..');

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

console.log('\nCAP Phase 2 — permit–execution binding conformance\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const {
  buildPermitExecutionStepBinding,
  buildPermitExecutionCommitment,
  verifyPermitExecutionCommitment,
  verifyPartialStepsPermitExecution,
  buildManifestCustodianCommitment,
  verifyManifestCustodianCommitment,
  PERMIT_EXECUTION_BINDING_SCHEMA,
  MANIFEST_CUSTODIAN_SCHEMA,
} = await import('@aevesa/verify');

const binding = buildPermitExecutionStepBinding('read_file', { path: '/vault/confidential/payroll.csv' });
ok('args_digest is 64 hex', /^[a-f0-9]{64}$/.test(binding.args_digest));
ok('binding_digest is 64 hex', /^[a-f0-9]{64}$/.test(binding.binding_digest));

const tamperedBinding = buildPermitExecutionStepBinding('read_file', { path: '/vault/other' });
ok('different args → different digest', tamperedBinding.args_digest !== binding.args_digest);

const partialSteps = [
  {
    index: 0,
    tool_name: 'read_file',
    args_digest: binding.args_digest,
    binding_digest: binding.binding_digest,
  },
];
const commitment = buildPermitExecutionCommitment(partialSteps);
ok('commitment schema', commitment.schema === PERMIT_EXECUTION_BINDING_SCHEMA);
ok('commitment verifies', verifyPermitExecutionCommitment(commitment).ok === true);
ok(
  'partial_steps align',
  verifyPartialStepsPermitExecution(partialSteps, commitment).ok === true,
);

const badCommitment = { ...commitment, binding_state_hash: 'f'.repeat(64) };
ok('tampered hash fails', verifyPermitExecutionCommitment(badCommitment).ok === false);

const custodian = buildManifestCustodianCommitment({
  session_id: 'demo-session',
  set_root: 'a'.repeat(64),
  witness_entry_hash: 'b'.repeat(64),
});
ok('custodian schema', custodian.schema === MANIFEST_CUSTODIAN_SCHEMA);
ok('custodian verifies', verifyManifestCustodianCommitment(custodian).ok === true);
ok(
  'custodian set_root check',
  verifyManifestCustodianCommitment(custodian, { set_root: 'a'.repeat(64) }).ok === true,
);

const specPe = join(repoRoot, 'spec/aevesa-permit-execution-binding-v1.json');
const specMc = join(repoRoot, 'spec/aevesa-session-manifest-custodian-v1.json');
ok('permit-execution spec exists', readFileSync(specPe, 'utf8').includes(PERMIT_EXECUTION_BINDING_SCHEMA));
ok('manifest-custodian spec exists', readFileSync(specMc, 'utf8').includes(MANIFEST_CUSTODIAN_SCHEMA));

console.log(`\nPermit–execution conformance: ${passed} checks passed.\n`);
