#!/usr/bin/env node
/**
 * Phase 1 — chain enforcement rollup unit conformance.
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

console.log('\nChain enforcement rollup — conformance\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const {
  rollupChainEnforcement,
  buildProofStrengthDisclosureDocument,
  PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
} = await import('@aevesa/verify');

const enforcedDoc = buildProofStrengthDisclosureDocument({
  enforcement_mode: 'enforced',
  capture_timing: 'pre_execution',
  pep_invariant: PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
  witness_mode: 'awaited_fail_closed',
  witness_persistence: 'postgres',
  external_transparency: 'rekor_metadata_only',
  generated_at: '2026-09-10T18:00:00.000Z',
});

const auditOnlyDoc = buildProofStrengthDisclosureDocument({
  enforcement_mode: 'audit_only',
  capture_timing: 'post_observed',
  pep_invariant: null,
  witness_mode: 'async',
  witness_persistence: 'memory_lab',
  external_transparency: 'none',
  generated_at: '2026-09-10T18:00:00.000Z',
});

const allEnforced = rollupChainEnforcement({
  member_receipts: [{ proof_strength_disclosure: enforcedDoc }, { proof_strength_disclosure: enforcedDoc }],
});
ok('all enforced → uniformly_enforced', allEnforced.uniformly_enforced === true);
ok('all enforced mode', allEnforced.chain_enforcement_mode === 'enforced');

const mixed = rollupChainEnforcement({
  member_receipts: [
    { proof_strength_disclosure: enforcedDoc },
    { proof_strength_disclosure: auditOnlyDoc },
    { proof_strength_disclosure: enforcedDoc },
  ],
});
ok('mixed chain mode', mixed.chain_enforcement_mode === 'mixed');
ok('mixed not uniformly enforced', mixed.uniformly_enforced === false);
ok('weakest link hop 1', mixed.weakest_link_index === 1);

const partialOnly = rollupChainEnforcement({
  partial_steps: [
    { index: 0, enforcement_mode: 'enforced' },
    { index: 1, enforcement_mode: 'audit_only' },
  ],
});
ok('partial_steps mixed', partialOnly.chain_enforcement_mode === 'mixed');

const unknown = rollupChainEnforcement({ member_receipts: [{ schema: 'liability-receipt/v1' }] });
ok('unknown when undisclosed', unknown.chain_enforcement_mode === 'unknown');

const forged = rollupChainEnforcement({
  member_receipts: [
    {
      schema: 'liability-receipt/v1',
      governance: {
        proof_strength_disclosure: {
          schema: 'aevesa.proof-strength-disclosure/v1',
          enforcement_mode: 'enforced',
          capture_timing: 'pre_execution',
          pep_invariant: PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
          witness_mode: 'awaited_fail_closed',
          witness_persistence: 'postgres',
          external_transparency: 'rekor_metadata_only',
          limitations: ['forged'],
          generated_at: '2026-09-10T18:00:00.000Z',
          disclosure_digest: '0'.repeat(64),
        },
      },
    },
  ],
});
ok('forged governance disclosure ignored', forged.chain_enforcement_mode === 'unknown');

const pathBoundVerified = rollupChainEnforcement({
  member_receipts: [{ governance: { proof_strength_disclosure: enforcedDoc } }],
  partial_steps: [{ index: 0, enforcement_mode: 'audit_only' }],
  member_receipt_verified_by_hop: { 0: true },
});
ok('partial_steps beat verified member hint', pathBoundVerified.chain_enforcement_mode === 'audit_only');

const pathBoundUnverified = rollupChainEnforcement({
  member_receipts: [{ governance: { proof_strength_disclosure: enforcedDoc } }],
  partial_steps: [{ index: 0, enforcement_mode: 'audit_only' }],
});
ok(
  'partial_steps ignored over unverified member (PC-01)',
  pathBoundUnverified.chain_enforcement_mode === 'enforced',
);

const absoluteWindow = rollupChainEnforcement({
  partial_steps: [
    { index: 35, step_index: 35, enforcement_mode: 'enforced' },
    { index: 36, step_index: 36, enforcement_mode: 'audit_only' },
  ],
});
ok('PC-12 absolute step_index weakest hop 36', absoluteWindow.weakest_link_index === 36);
ok('PC-12 absolute window mixed mode', absoluteWindow.chain_enforcement_mode === 'mixed');

const entryHashAligned = rollupChainEnforcement({
  manifest_members: [
    { step_index: 40, entry_hash: 'a'.repeat(64) },
    { step_index: 41, entry_hash: 'b'.repeat(64) },
  ],
  partial_steps: [
    { index: 0, entry_hash: 'a'.repeat(64), enforcement_mode: 'enforced' },
    { index: 1, entry_hash: 'b'.repeat(64), enforcement_mode: 'audit_only' },
  ],
});
ok(
  'PC-12 entry_hash aligns window index to manifest step_index',
  entryHashAligned.weakest_link_index === 41,
);

console.log(`\n${passed} checks passed.\n`);
