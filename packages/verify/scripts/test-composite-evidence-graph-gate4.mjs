#!/usr/bin/env node
/**
 * Gate 4 — composite evidence graph conformance (SCITT-aligned profiles).
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '../../..');
const verifyPkg = join(__dirname, '..');

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

function expectVerdict(label, result, expected) {
  ok(`${label} → ${expected}`, result.verdict === expected);
}

console.log('\nGate 4 — composite evidence graph (SCITT profiles)\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const { evaluateCompositeEvidenceGraph } = await import('@aevesa/verify');
const evalGraph = (doc, profile) => evaluateCompositeEvidenceGraph(doc, profile);

const capPath = join(verifyPkg, 'fixtures/cap-session-proof-demo.json');
const capFull = JSON.parse(readFileSync(capPath, 'utf8'));

const capDigestOnly = { ...capFull, member_receipts: [] };
const capTerminalOnly = {
  schema: 'aevesa.compositional-accountability/v1',
  session_id: capFull.session_id,
  terminal_receipt: capFull.terminal_receipt,
};

const { buildCarrierMgaAcceptanceDemoSnapshot } = await import(
  join(repoRoot, 'private-backend/src/services/evidence/carrierMgaAcceptanceDemoService.js')
);
const mgaSnapshot = await buildCarrierMgaAcceptanceDemoSnapshot();
const mgaKit = mgaSnapshot.carrier_mga_acceptance_kit;
const mgaHashOnly = { ...mgaKit };
delete mgaHashOnly.member_documents;

const {
  AEVESA_MIXED_ENFORCEMENT_MANIFEST,
  AEVESA_MIXED_ENFORCEMENT_MEMBER_RECEIPTS,
  AEVESA_MIXED_ENFORCEMENT_TERMINAL_RECEIPT,
} = await import(join(repoRoot, 'aevesa-app-site/src/js/mixedEnforcementDemoData.js'));

const mixedBundle = {
  schema: 'aevesa.compositional-accountability/v1',
  session_id: 'wave15-mixed-enforcement-demo',
  manifest: AEVESA_MIXED_ENFORCEMENT_MANIFEST,
  terminal_receipt: AEVESA_MIXED_ENFORCEMENT_TERMINAL_RECEIPT,
  member_receipts: AEVESA_MIXED_ENFORCEMENT_MEMBER_RECEIPTS,
};

console.log('\n--- Session proof graphs ---\n');

const fullCarrier = evalGraph(capFull, 'carrier_handoff_closed_world');
expectVerdict('cap fixture full bundled carrier profile', fullCarrier, 'unknown');
ok('cap demo session_proof_complete but not carrier graph pass', fullCarrier.statement_checks?.session_proof_complete === true);
ok('cap demo closure member_verification_required', fullCarrier.policy_checks?.closure_verdict === 'member_verification_required');

const digestCarrier = evalGraph(capDigestOnly, 'carrier_handoff_closed_world');
expectVerdict('cap digest-only carrier profile', digestCarrier, 'unknown');

const terminalPortal = evalGraph(capTerminalOnly, 'portal_open_world');
expectVerdict('cap terminal-only portal profile', terminalPortal, 'unknown');

const mixedCarrier = evalGraph(mixedBundle, 'carrier_handoff_closed_world');
expectVerdict('mixed enforcement carrier profile', mixedCarrier, 'warn');

const mixedPortal = evalGraph(mixedBundle, 'portal_open_world');
ok('mixed enforcement portal warn or unknown', ['warn', 'unknown'].includes(mixedPortal.verdict));

console.log('\n--- MGA composed pack graphs ---\n');

const mgaFull = evalGraph(mgaKit, 'mga_handoff_closed_world');
expectVerdict('MGA demo bundled mga profile', mgaFull, 'pass');

const mgaHash = evalGraph(mgaHashOnly, 'mga_handoff_closed_world');
expectVerdict('MGA hash-only mga profile', mgaHash, 'unknown');

console.log('\n--- SCITT incomplete-set discipline ---\n');

ok('digest-only not pass on carrier profile', digestCarrier.verdict !== 'pass');
ok('hash-only MGA not pass on mga profile', mgaHash.verdict !== 'pass');
ok('full cap bundled does not imply carrier_review_ready', fullCarrier.policy_checks?.carrier_review_ready === false);
ok('digest-only missing member_receipts', digestCarrier.missing_statements.includes('member_receipts'));

console.log('\n--- Egress proxy provenance downgrade (Wave 17-D Phase 5) ---\n');

const capExportSelfAttested = {
  ok: true,
  bundle: capFull,
  proxy_attribution_provenance: {
    assurance_tier: 'self_attested',
    independently_observed_claim_allowed: false,
  },
};
const proxyDowngrade = evalGraph(capExportSelfAttested, 'carrier_handoff_closed_world');
ok('self_attested proxy broker downgrade flag', proxyDowngrade.policy_checks?.proxy_broker_downgrade_required === true);
ok(
  'self_attested proxy not independently observed',
  proxyDowngrade.policy_checks?.proxy_independently_observed_claim_allowed === false,
);

console.log(`\n${passed} checks passed.\n`);
