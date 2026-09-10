#!/usr/bin/env node
/**
 * CAP Phase 3 — full member_receipts[] per-hop offline verification conformance.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const verifyPkg = join(__dirname, '..');
const repoRoot = join(verifyPkg, '../..');
const portalDataUrl = pathToFileURL(
  join(repoRoot, 'aevesa-app-site/src/js/setCompletenessDemoData.js'),
).href;

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

console.log('\nCAP Phase 3 — member receipts conformance\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const {
  verifySessionProof,
  verifyReceipt,
  verifyMemberReceiptsArgsAlignment,
  computeSessionProofDigest,
  SESSION_PROOF_SCHEMA,
  buildManifestCustodianCommitment,
} = await import('@aevesa/verify');

const {
  AEVESA_SET_COMPLETENESS_MANIFEST,
  AEVESA_SET_COMPLETENESS_TERMINAL_RECEIPT,
  AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS,
} = await import(portalDataUrl);

ok('member receipts exported', Array.isArray(AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS));
ok(
  'member count matches declared_count',
  AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS.length === AEVESA_SET_COMPLETENESS_MANIFEST.declared_count,
);

for (let i = 0; i < AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS.length; i += 1) {
  const receipt = AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS[i];
  const structural = verifyReceipt(receipt);
  ok(`hop ${i} receipt valid`, structural.isValid === true);
  const expected = AEVESA_SET_COMPLETENESS_MANIFEST.members[i]?.receipt_digest;
  const actual = receipt?.integrity?.receipt_digest;
  ok(`hop ${i} digest matches manifest`, String(actual).toLowerCase() === String(expected).toLowerCase());
}

const partialSteps = AEVESA_SET_COMPLETENESS_TERMINAL_RECEIPT?.partial_path?.partial_steps ?? [];
const argsAlign = verifyMemberReceiptsArgsAlignment(
  partialSteps,
  AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS,
);
ok('member args_digest aligned with partial_steps', argsAlign.ok === true);

const witnessEntry = String(
  AEVESA_SET_COMPLETENESS_TERMINAL_RECEIPT?.proof?.primary_anchor?.entry_hash || '',
)
  .trim()
  .toLowerCase();
const manifest_custodian = buildManifestCustodianCommitment({
  session_id: AEVESA_SET_COMPLETENESS_MANIFEST.session_id,
  set_root: AEVESA_SET_COMPLETENESS_MANIFEST.set_root,
  witness_entry_hash: witnessEntry || null,
});

const bundleBody = {
  schema: SESSION_PROOF_SCHEMA,
  session_id: AEVESA_SET_COMPLETENESS_MANIFEST.session_id,
  manifest: AEVESA_SET_COMPLETENESS_MANIFEST,
  terminal_receipt: AEVESA_SET_COMPLETENESS_TERMINAL_RECEIPT,
  member_receipts: AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS,
  manifest_custodian,
};
const bundle = {
  ...bundleBody,
  bundle_digest: computeSessionProofDigest(bundleBody),
};
const verified = verifySessionProof(bundle);
ok('full CAP bundle ok', verified.ok === true);
ok('memberReceiptsVerified check', verified.checks.memberReceiptsVerified === true);

const tamperedMembers = [...AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS];
tamperedMembers[0] = {
  ...tamperedMembers[0],
  side_effects: {
    ...tamperedMembers[0].side_effects,
    action: {
      ...tamperedMembers[0].side_effects.action,
      args_digest: 'f'.repeat(64),
    },
  },
};
const badArgs = verifyMemberReceiptsArgsAlignment(partialSteps, tamperedMembers);
ok('tampered args_digest fails alignment', badArgs.ok === false);

console.log(`\nMember receipts conformance: ${passed} checks passed.\n`);
