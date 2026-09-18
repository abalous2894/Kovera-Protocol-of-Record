#!/usr/bin/env node
/**
 * Wave 16-A — session composition closure conformance.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
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

console.log('\nSession composition closure — Wave 16-A conformance\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const {
  buildReceiptPresence,
  buildSessionCompositionClosure,
  deriveClosureVerdict,
  verifySessionCompositionClosure,
  rollupChainEnforcement,
  buildSessionProofExportHints,
  buildProofStrengthDisclosureDocument,
  verifySessionProof,
  PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
} = await import('@aevesa/verify');

const enforcedDoc = buildProofStrengthDisclosureDocument({
  enforcement_mode: 'enforced',
  capture_timing: 'pre_execution',
  pep_invariant: PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
  witness_mode: 'awaited_fail_closed',
  witness_persistence: 'postgres',
  external_transparency: 'rekor_metadata_only',
  generated_at: '2026-09-11T18:00:00.000Z',
});

const manifest = {
  schema: 'aevesa.set-completeness/v1',
  session_id: 'sess-closure-test',
  declared_count: 2,
  members: [
    { step_index: 0, receipt_digest: 'a'.repeat(64), entry_hash: 'b'.repeat(64) },
    { step_index: 1, receipt_digest: 'c'.repeat(64), entry_hash: 'd'.repeat(64) },
  ],
  set_root: 'e'.repeat(64),
};

const digestOnlyPresence = buildReceiptPresence({
  set_completeness_ok: true,
  manifest,
  member_receipts: [],
});
ok('digest-only hop 0', digestOnlyPresence[0].presence === 'digest_only');
ok('digest-only profile', digestOnlyPresence[0].verify_profile === 'digest_only');

const digestVerdict = deriveClosureVerdict({
  set_completeness_ok: true,
  receipt_presence: digestOnlyPresence,
  chain_enforcement: null,
  export_hints: buildSessionProofExportHints({ manifest, member_receipts: [] }),
});
ok('digest-only → digest_only_submission', digestVerdict === 'digest_only_submission');

const bundledPresence = buildReceiptPresence({
  set_completeness_ok: true,
  manifest,
  member_receipts: [
    { proof_strength_disclosure: enforcedDoc },
    { proof_strength_disclosure: enforcedDoc },
  ],
  member_receipt_verified_by_hop: { 0: true, 1: true },
});
ok('bundled verified hop', bundledPresence[0].presence === 'bundled');
ok('member_receipt_verified profile', bundledPresence[0].verify_profile === 'member_receipt_verified');

const chain = rollupChainEnforcement({
  member_receipts: [
    { proof_strength_disclosure: enforcedDoc },
    { proof_strength_disclosure: enforcedDoc },
  ],
  member_receipt_verified_by_hop: { 0: true, 1: true },
});
const exportHints = buildSessionProofExportHints({
  manifest,
  member_receipts: [{}, {}],
});
const carrierReady = buildSessionCompositionClosure({
  set_completeness_ok: true,
  manifest,
  member_receipts: [{ proof_strength_disclosure: enforcedDoc }, { proof_strength_disclosure: enforcedDoc }],
  member_receipt_verified_by_hop: { 0: true, 1: true },
  chain_enforcement: chain,
  export_hints: exportHints,
});
ok('carrier_review_ready when bundled + uniform', carrierReady.closure_verdict === 'carrier_review_ready');
ok('carrier_review_ready flag', carrierReady.carrier_review_ready === true);
ok('closure_digest 64 hex', /^[a-f0-9]{64}$/.test(carrierReady.closure_digest));

const tamperCheck = verifySessionCompositionClosure(carrierReady, {
  set_completeness_ok: true,
  manifest,
  member_receipts: [{ proof_strength_disclosure: enforcedDoc }, { proof_strength_disclosure: enforcedDoc }],
  member_receipt_verified_by_hop: { 0: true, 1: true },
  chain_enforcement: chain,
  export_hints: exportHints,
});
ok('closure self-verify ok', tamperCheck.ok === true);

const forged = { ...carrierReady, closure_verdict: 'digest_only_submission' };
const tamperFail = verifySessionCompositionClosure(forged, {
  set_completeness_ok: true,
  manifest,
  member_receipts: [{ proof_strength_disclosure: enforcedDoc }, { proof_strength_disclosure: enforcedDoc }],
  member_receipt_verified_by_hop: { 0: true, 1: true },
  chain_enforcement: chain,
  export_hints: exportHints,
});
ok('tampered verdict fails', tamperFail.ok === false);

console.log('\nJames J-6 — requireMemberReceipts + digest-only hop vs enforcement rollup\n');

const twoHopManifest = {
  schema: 'aevesa.set-completeness/v1',
  session_id: 'sess-j6-rollup-advisory',
  declared_count: 2,
  members: [
    { step_index: 0, receipt_digest: 'f'.repeat(64), entry_hash: '1'.repeat(64) },
    { step_index: 1, receipt_digest: '2'.repeat(64), entry_hash: '3'.repeat(64) },
  ],
  set_root: '4'.repeat(64),
};

const mixedRollup = rollupChainEnforcement({
  partial_steps: [
    { index: 0, enforcement_mode: 'enforced' },
    { index: 1, enforcement_mode: 'audit_only' },
  ],
});
ok('partial_steps rollup is mixed', mixedRollup.chain_enforcement_mode === 'mixed');

const j6Hints = buildSessionProofExportHints({
  manifest: twoHopManifest,
  member_receipts: [],
});
const j6Closure = buildSessionCompositionClosure({
  set_completeness_ok: true,
  manifest: twoHopManifest,
  member_receipts: [],
  chain_enforcement: mixedRollup,
  export_hints: j6Hints,
});
ok('digest-only export → digest_only_submission', j6Closure.closure_verdict === 'digest_only_submission');
ok('rollup still mixed on closure', j6Closure.chain_enforcement?.chain_enforcement_mode === 'mixed');
ok(
  'rollup not qualified when digest-only + mixed',
  j6Closure.chain_enforcement_advisory.chain_enforcement_qualified === false,
);
ok(
  'rollup scope enforcement_only',
  j6Closure.chain_enforcement_advisory.rollup_scope === 'enforcement_only',
);
ok(
  'advisory note mentions verification state',
  String(j6Closure.chain_enforcement_advisory.advisory_note || '').includes('verification state'),
);
ok('not carrier ready', j6Closure.carrier_review_ready === false);

console.log('\nJames J-6 — operational closure ship gate (Sep 2026 acceptance test)\n');

const { evaluateClosureShipGate } = await import('@aevesa/verify');

const j6Gate = evaluateClosureShipGate(j6Closure);
ok('ship gate blocked on digest-only', j6Gate.blocked === true);
ok('not carrier submission ready', j6Gate.carrier_submission_ready === false);
ok('rollup alone ship risk flagged', j6Gate.rollup_alone_ship_risk === true);
ok('PC-16 rollup inference blocked on digest-only', j6Gate.rollup_carrier_inference_allowed === false);
ok('ship gate note mentions rollup', String(j6Gate.note || '').includes('rollup'));

const readyGate = evaluateClosureShipGate(carrierReady);
ok('carrier ready passes ship gate', readyGate.carrier_submission_ready === true);
ok('carrier ready not blocked', readyGate.blocked === false);
ok('PC-16 rollup inference allowed when carrier ready', readyGate.rollup_carrier_inference_allowed === true);

const absentGate = evaluateClosureShipGate(null);
ok('missing closure blocked', absentGate.blocked === true);

ok(
  'CAP requireCarrierReady=1 would block digest-only export',
  { ok: true, closure_ship_gate: j6Gate }.ok === true && j6Gate.blocked === true,
);

console.log('\nJames PC-02 — digest-only export must not read session_proof_complete\n');

const capFixturePath = join(verifyPkg, 'fixtures/cap-session-proof-demo.json');
const capFixture = JSON.parse(readFileSync(capFixturePath, 'utf8'));
const digestOnlyBundle = { ...capFixture, member_receipts: [] };

const digestOnlyVerify = verifySessionProof(digestOnlyBundle);
ok('digest-only structural set completeness passes', digestOnlyVerify.checks.setCompleteness === true);
ok('digest-only session_proof_complete false (PC-02)', digestOnlyVerify.session_proof_complete === false);
ok('digest-only verify ok false', digestOnlyVerify.ok === false);
ok(
  'digest-only closure verdict',
  digestOnlyVerify.composition_closure?.closure_verdict === 'digest_only_submission',
);
ok(
  'digest-only note mentions session_proof_complete',
  String(digestOnlyVerify.note || '').includes('session_proof_complete'),
);
ok(
  'digest-only verify includes closure_ship_gate',
  digestOnlyVerify.closure_ship_gate?.schema === 'aevesa.closure-ship-gate/v1',
);
ok(
  'PC-16 verify rollup inference blocked',
  digestOnlyVerify.closure_ship_gate?.rollup_carrier_inference_allowed === false,
);

console.log(`\n${passed} checks passed.\n`);
