#!/usr/bin/env node
/**
 * Phase 3 — session composition guidance (GL3/AT7 hints + carrier disclosure).
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

console.log('\nSession composition guidance — conformance\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const {
  buildSessionCompositionGuidance,
  buildCarrierChainCompositionDisclosure,
  OWASP_ASI_GL3_HINT,
  OWASP_AT7_HINT,
} = await import('@aevesa/verify');

const mixed = buildSessionCompositionGuidance({
  chain_enforcement: {
    chain_enforcement_mode: 'mixed',
    uniformly_enforced: false,
    weakest_link_index: 1,
  },
  export_hints: { require_member_receipt_verification: false },
});
ok('schema', mixed.schema === 'aevesa.session-composition-guidance/v1');
ok('GL3 hint present', mixed.owasp_asi_gl3_hint === OWASP_ASI_GL3_HINT);
ok('AT7 hint present', mixed.owasp_at7_hint === OWASP_AT7_HINT);
ok('mixed mode', mixed.chain_enforcement_mode === 'mixed');
ok('weakest link in footnote', mixed.proof_trace_footnote.includes('weakest link hop 1'));

const requireMembers = buildSessionCompositionGuidance({
  chain_enforcement: { chain_enforcement_mode: 'enforced', uniformly_enforced: true },
  export_hints: { require_member_receipt_verification: true },
});
ok('require members flag', requireMembers.require_member_receipt_verification === true);
ok('AT7 in require-members footnote', requireMembers.proof_trace_footnote.includes('member_receipts'));

const carrier = buildCarrierChainCompositionDisclosure({
  chain_enforcement: {
    chain_enforcement_mode: 'mixed',
    uniformly_enforced: false,
    weakest_link_index: 1,
  },
  export_hints: { require_member_receipt_verification: false },
});
ok('carrier chain mode', carrier.chain_enforcement_mode === 'mixed');
ok('egress schema ref v2 default', carrier.egress_attestation_schema === 'aevesa.egress-attestation/v2');

console.log(`\n${passed} checks passed.\n`);
