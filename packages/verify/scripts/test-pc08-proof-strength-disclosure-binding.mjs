#!/usr/bin/env node
/**
 * James PC-08 — proof_strength_disclosure digest binding conformance.
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

console.log('\nJames PC-08 — proof_strength_disclosure digest binding\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const {
  buildProofStrengthDisclosureDocument,
  PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
  applyProofStrengthDisclosureDigestBinding,
  verifyProofStrengthDisclosureReceiptBinding,
  verifyReceipt,
  computeReceiptDigest,
  computeSetCompletenessRoot,
  verifyManifestMemberDisclosureDigests,
} = await import('@aevesa/verify');

const disclosure = buildProofStrengthDisclosureDocument({
  enforcement_mode: 'enforced',
  capture_timing: 'pre_execution',
  pep_invariant: PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
  witness_mode: 'awaited_fail_closed',
  witness_persistence: 'postgres',
  external_transparency: 'rekor_metadata_only',
  generated_at: '2026-09-12T18:00:00.000Z',
});

const capFixture = JSON.parse(readFileSync(join(verifyPkg, 'fixtures/cap-session-proof-demo.json'), 'utf8'));
const baseReceipt = structuredClone(capFixture.member_receipts[0]);
baseReceipt.governance = {
  ...(baseReceipt.governance && typeof baseReceipt.governance === 'object' ? baseReceipt.governance : {}),
  proof_strength_disclosure: disclosure,
};

applyProofStrengthDisclosureDigestBinding(baseReceipt);
ok('binding applied', baseReceipt.proof_strength_disclosure_digest === disclosure.disclosure_digest);

baseReceipt.integrity = {
  receipt_digest: computeReceiptDigest(baseReceipt),
  signature_alg: 'none',
  signature: null,
  manifest_signature_jws: null,
};

const verified = verifyReceipt(baseReceipt);
ok('bound receipt verifies', verified.isValid === true);

const legacy = {
  ...baseReceipt,
  proof_strength_disclosure_digest: undefined,
  integrity: {
    ...baseReceipt.integrity,
    receipt_digest: computeReceiptDigest({
      ...baseReceipt,
      proof_strength_disclosure_digest: undefined,
    }),
  },
};
ok('legacy receipt without digest pillar still verifies', verifyReceipt(legacy).isValid === true);

const forgedBinding = {
  ...baseReceipt,
  proof_strength_disclosure_digest: 'b'.repeat(64),
  integrity: {
    ...baseReceipt.integrity,
    receipt_digest: computeReceiptDigest({
      ...baseReceipt,
      proof_strength_disclosure_digest: 'b'.repeat(64),
    }),
  },
};
ok('forged digest mismatch fails binding', verifyProofStrengthDisclosureReceiptBinding(forgedBinding).ok === false);
ok('forged digest fails verifyReceipt', verifyReceipt(forgedBinding).isValid === false);

const postHocGovernance = {
  ...legacy,
  governance: {
    proof_strength_disclosure: buildProofStrengthDisclosureDocument({
      enforcement_mode: 'audit_only',
      capture_timing: 'post_observed',
      witness_mode: 'none',
      witness_persistence: 'memory_lab',
      external_transparency: 'none',
      generated_at: '2026-09-12T18:01:00.000Z',
    }),
  },
};
ok(
  'post-hoc governance without digest pillar does not break legacy verify',
  verifyReceipt(postHocGovernance).isValid === true,
);

const sessionId = String(baseReceipt.session?.session_id || 'sess-pc08');
const members = [
  {
    step_index: 0,
    receipt_digest: baseReceipt.integrity.receipt_digest,
    entry_hash: String(baseReceipt.proof?.primary_anchor?.entry_hash || 'a'.repeat(64)).toLowerCase(),
    proof_strength_disclosure_digest: disclosure.disclosure_digest,
  },
];
const set_root = computeSetCompletenessRoot({
  session_id: sessionId,
  declared_count: 1,
  members,
});
const manifest = {
  schema: 'aevesa.set-completeness/v1',
  session_id: sessionId,
  declared_count: 1,
  members,
  set_root,
  terminal_receipt_digest: baseReceipt.integrity.receipt_digest,
};

const manifestAlign = verifyManifestMemberDisclosureDigests(manifest, [baseReceipt]);
ok('manifest member disclosure digest aligns', manifestAlign.ok === true);

const mismatchedManifest = {
  ...manifest,
  members: [{ ...members[0], proof_strength_disclosure_digest: 'c'.repeat(64) }],
};
ok(
  'manifest member disclosure mismatch fails alignment',
  verifyManifestMemberDisclosureDigests(mismatchedManifest, [baseReceipt]).ok === false,
);

console.log(`\n${passed} checks passed.\n`);
