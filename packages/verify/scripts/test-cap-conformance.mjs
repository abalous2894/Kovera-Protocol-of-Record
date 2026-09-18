#!/usr/bin/env node
/**
 * CAP Phase 0 — Compositional Accountability session proof conformance.
 */
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
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

console.log('\nCAP Phase 0 — session proof conformance\n');

const buildVerify = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('@aevesa/verify build succeeded', buildVerify.status === 0);

const {
  verifySessionProof,
  computeSessionProofDigest,
  SESSION_PROOF_SCHEMA,
  SESSION_PROOF_SKU,
  SESSION_PROOF_VERIFY_SCHEMA,
} = await import('@aevesa/verify');

const {
  AEVESA_SET_COMPLETENESS_MANIFEST,
  AEVESA_SET_COMPLETENESS_TERMINAL_RECEIPT,
  AEVESA_SET_COMPLETENESS_MEMBER_RECEIPTS,
} = await import(portalDataUrl);

const { buildManifestCustodianCommitment } = await import('@aevesa/verify');

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
ok('verify schema', verified.schema === SESSION_PROOF_VERIFY_SCHEMA);
ok('verify sku', verified.sku === SESSION_PROOF_SKU);
ok('verify ok', verified.ok === true);
ok('session proof complete', verified.session_proof_complete === true);
ok('set completeness', verified.checks.setCompleteness === true);
ok('partial path aligned', verified.checks.partialPathMembersAligned === true);
ok('terminal receipt valid', verified.checks.terminalReceiptValid === true);
ok('capability budget valid', verified.checks.capabilityBudgetValid === true);
ok('capability monotonic', verified.checks.capabilityMonotonic === true);
ok('permit execution valid', verified.checks.permitExecutionValid === true);
ok('manifest custodian valid', verified.checks.manifestCustodianValid === true);
ok('member receipts verified', verified.checks.memberReceiptsVerified === true);
ok('member args aligned', verified.checks.memberArgsAligned === true);

const tampered = {
  ...bundle,
  session_id: 'tampered-session',
};
const bad = verifySessionProof(tampered);
ok('tampered session_id fails', bad.ok === false);

const digest = computeSessionProofDigest(bundle);
ok('bundle_digest matches', digest === bundle.bundle_digest);

const fixturePath = join(verifyPkg, 'fixtures/cap-session-proof-demo.json');
if (!existsSync(fixturePath)) {
  const gen = spawnSync('node', ['scripts/generate-cap-fixture.mjs'], {
    cwd: verifyPkg,
    stdio: 'inherit',
  });
  ok('generate fixture', gen.status === 0);
}
ok('fixture exists', existsSync(fixturePath));
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));
const fixtureVerify = verifySessionProof(fixture);
ok('fixture verifies offline', fixtureVerify.ok === true);

const cli = spawnSync(
  'node',
  ['src/cli.js', 'verify-session', fixturePath, '--summary'],
  { cwd: verifyPkg, stdio: 'pipe', encoding: 'utf8' },
);
ok('CLI verify-session exit 0', cli.status === 0);
ok('CLI summary mentions session_proof_complete', cli.stdout.includes('session_proof_complete'));
ok('CLI summary mentions closure_verdict', cli.stdout.includes('closure_verdict'));
ok('CLI summary mentions closure_ship_gate.blocked', cli.stdout.includes('closure_ship_gate.blocked'));
ok('CLI summary mentions rollup_carrier_inference_allowed', cli.stdout.includes('rollup_carrier_inference_allowed'));

const specPath = join(repoRoot, 'spec/aevesa-cap-v1.json');
ok('open spec exists', readFileSync(specPath, 'utf8').includes('aevesa.compositional-accountability/v1'));

const capDoc = join(repoRoot, 'docs/standards/CAP_V1.md');
ok('CAP_V1 doc', readFileSync(capDoc, 'utf8').includes('verify-session'));

const routesSrc = readFileSync(
  join(repoRoot, 'private-backend/src/routes/openEvidenceRoutes.js'),
  'utf8',
);
ok('cap-session-demo route', routesSrc.includes("router.get('/cap-session-demo'"));

console.log(`\nCAP conformance: ${passed} checks passed.\n`);
