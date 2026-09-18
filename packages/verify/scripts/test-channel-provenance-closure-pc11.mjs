#!/usr/bin/env node
/**
 * PC-11 — channel provenance content_binding + composition closure downgrade.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const verifyPkg = join(dirname(fileURLToPath(import.meta.url)), '..');

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

console.log('\nChannel provenance closure — PC-11 conformance\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const {
  verifyChannelProvenanceBundle,
  buildChannelProvenanceContentBindingReport,
  buildSessionCompositionClosure,
  buildSessionProofExportHints,
  rollupChainEnforcement,
  buildProofStrengthDisclosureDocument,
  PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
  computeChannelProvenanceDigest,
  computeClassificationDigest,
} = await import('@aevesa/verify');

const fixedSources = [
  {
    source_id: 'mandate-digest-only',
    classification: 'delegated_authority',
    content_digest: 'a'.repeat(64),
    content_binding: 'digest_only',
    origin: 'registry.proxy',
  },
  {
    source_id: 'env-fetch',
    classification: 'environmental',
    content_digest: 'b'.repeat(64),
    content_binding: 'content_bound',
    origin: 'mcp.fetch',
  },
];

const bindingReport = buildChannelProvenanceContentBindingReport(fixedSources);
ok('digest-only delegated in report', bindingReport.has_digest_only_delegated === true);

const channel_provenance = {
  schema: 'aevesa.channel-provenance/v1',
  session_id: 'sess-pc11-channel',
  decision_id: 'sess-pc11-channel:tool.run',
  sources: fixedSources,
  delegated_digest: computeClassificationDigest(fixedSources, 'delegated_authority'),
  environmental_digest: computeClassificationDigest(fixedSources, 'environmental'),
  system_digest: computeClassificationDigest(fixedSources, 'system'),
  channel_provenance_digest: computeChannelProvenanceDigest({
    session_id: 'sess-pc11-channel',
    decision_id: 'sess-pc11-channel:tool.run',
    sources: fixedSources,
  }),
};

const channelVerify = verifyChannelProvenanceBundle(channel_provenance);
ok('channel manifest verifies', channelVerify.ok === true);
ok('verify exposes digestOnlyDelegatedPresent', channelVerify.checks.digestOnlyDelegatedPresent === true);

const enforcedDoc = buildProofStrengthDisclosureDocument({
  enforcement_mode: 'enforced',
  capture_timing: 'pre_execution',
  pep_invariant: PEP_INVARIANT_RECEIPT_BEFORE_ACTION,
  witness_mode: 'awaited_fail_closed',
  witness_persistence: 'postgres',
  external_transparency: 'rekor_metadata_only',
  generated_at: '2026-09-11T20:00:00.000Z',
});

const manifest = {
  schema: 'aevesa.set-completeness/v1',
  session_id: 'sess-pc11-channel',
  declared_count: 1,
  members: [{ step_index: 0, receipt_digest: 'c'.repeat(64), entry_hash: 'd'.repeat(64) }],
  set_root: 'e'.repeat(64),
};

const chain = rollupChainEnforcement({
  member_receipts: [{ proof_strength_disclosure: enforcedDoc }],
  member_receipt_verified_by_hop: { 0: true },
});
const exportHints = buildSessionProofExportHints({ manifest, member_receipts: [{}] });

const closureInput = {
  set_completeness_ok: true,
  manifest,
  member_receipts: [{ proof_strength_disclosure: enforcedDoc }],
  member_receipt_verified_by_hop: { 0: true },
  chain_enforcement: chain,
  export_hints: exportHints,
};

const withoutChannel = buildSessionCompositionClosure(closureInput);
ok('without channel can be carrier ready', withoutChannel.closure_verdict === 'carrier_review_ready');

const withChannel = buildSessionCompositionClosure({
  ...closureInput,
  channel_provenance,
});

ok(
  'digest-only delegated downgrades closure',
  withChannel.closure_verdict === 'digest_only_submission',
);
ok('not carrier ready with digest-only mandate', withChannel.carrier_review_ready === false);
ok(
  'channel advisory cites mandate source',
  withChannel.channel_provenance_advisory?.digest_only_delegated_source_ids?.includes(
    'mandate-digest-only',
  ),
);

console.log(`\n${passed} checks passed.\n`);
