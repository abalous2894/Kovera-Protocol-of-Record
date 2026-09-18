#!/usr/bin/env node
/**
 * Wave 17-A — egress attestation v2 (run_id, attribution_timing) conformance (James J-1/J-2).
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const verifyRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

const buildVerify = spawnSync('npm', ['run', 'build'], {
  cwd: verifyRoot,
  stdio: 'inherit',
});
if (buildVerify.status !== 0) process.exit(buildVerify.status ?? 1);

const {
  buildEgressAttestationV2Document,
  verifyEgressAttestationBundle,
  detectEvidenceType,
  EGRESS_ATTESTATION_V2_SCHEMA,
} = await import('@aevesa/verify');

let passed = 0;
function ok(label, cond) {
  if (!cond) {
    console.error(`  ✗ ${label}`);
    process.exit(1);
  }
  passed += 1;
  console.log(`  ✓ ${label}`);
}

console.log('\nWave 17-A — Egress attestation v2 conformance\n');

const doc = buildEgressAttestationV2Document({
  session_id: 'james-j1-attribution-demo',
  attestation_mode: 'egress_proxy_split',
  mcp_pep_bound: false,
  observed_channels: ['https.outbound'],
  run_id: 'run-james-j1-001',
  intent_receipt_digest: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
  registry_manifest_digest: 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
  attribution_timing: 'pre_fetch',
  generated_at: '2026-09-11T00:00:00.000Z',
});

ok('schema v2', doc.schema === EGRESS_ATTESTATION_V2_SCHEMA);
ok('run_id present', doc.run_id === 'run-james-j1-001');
ok('attribution_timing pre_fetch', doc.attribution_timing === 'pre_fetch');

const verify = verifyEgressAttestationBundle(doc);
ok('offline verify ok', verify.ok === true);
ok('digest matches', verify.checks.digestMatches === true);
ok('attribution profile complete', verify.checks.attributionProfileComplete === true);
ok('pre_fetch intent bound', verify.checks.preFetchIntentBound === true);

const missingIntent = buildEgressAttestationV2Document({
  session_id: 'james-j1-attribution-demo',
  attestation_mode: 'observe_only',
  mcp_pep_bound: false,
  run_id: 'run-james-j2-fail',
  attribution_timing: 'pre_fetch',
  generated_at: '2026-09-11T00:00:00.000Z',
});
const failVerify = verifyEgressAttestationBundle(missingIntent);
ok('pre_fetch without intent fails', failVerify.ok === false);
ok('fail note mentions intent', String(failVerify.note || '').includes('intent_receipt_digest'));

const networkObserve = buildEgressAttestationV2Document({
  session_id: 'james-j2-network',
  attestation_mode: 'observe_only',
  mcp_pep_bound: false,
  run_id: 'run-james-j2-network',
  attribution_timing: 'network_observe',
  generated_at: '2026-09-11T00:00:00.000Z',
});
ok('network_observe verify ok', verifyEgressAttestationBundle(networkObserve).ok === true);

const detect = detectEvidenceType(doc);
ok('detectEvidenceType egress_attestation', detect.kind === 'egress_attestation');

console.log(`\n${passed} checks passed\n`);
