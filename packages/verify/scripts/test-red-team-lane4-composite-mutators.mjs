#!/usr/bin/env node
/**
 * Wave 18-A Lane 4 — composite mutator fixtures (SCITT graph must fail closed).
 *
 * Fixtures: packages/verify/fixtures/red-team/*-mutator.json
 * Playbook: docs/security/AEVESA_RED_TEAM_PLAYBOOK.md
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const verifyPkg = join(__dirname, '..');
const fixturesDir = join(verifyPkg, 'fixtures/red-team');

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

function loadMutatorFixture(name) {
  const raw = JSON.parse(readFileSync(join(fixturesDir, name), 'utf8'));
  const meta = raw._mutator_meta ?? {};
  const doc = { ...raw };
  delete doc._mutator_meta;
  return { doc, meta };
}

function expectVerdict(label, result, expected) {
  ok(`${label} → ${expected}`, result.verdict === expected);
}

console.log('\nWave 18-A Lane 4 — composite mutator fixtures\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const { evaluateCompositeEvidenceGraph, verifyCarrierMgaAcceptanceKit } = await import('@aevesa/verify');

const { doc: terminalOnly, meta: terminalMeta } = loadMutatorFixture(
  'cap-terminal-only-portal-mutator.json',
);
const { doc: digestOnly, meta: digestMeta } = loadMutatorFixture(
  'cap-digest-only-carrier-mutator.json',
);
const { doc: mgaHashOnly, meta: mgaMeta } = loadMutatorFixture(
  'mga-exporter-verify-ok-without-body-mutator.json',
);

ok('terminal-only fixture meta', terminalMeta.id === 'cap-terminal-only-portal');
ok('digest-only fixture meta', digestMeta.id === 'cap-digest-only-carrier');
ok('mga exporter fixture meta', mgaMeta.id === 'mga-exporter-verify-ok-without-body');

console.log('\n--- Mutator oracles (evaluateCompositeEvidenceGraph) ---\n');

const terminalGraph = evaluateCompositeEvidenceGraph(terminalOnly, terminalMeta.profile);
expectVerdict('terminal-only portal profile', terminalGraph, terminalMeta.expected_verdict);
ok('terminal-only missing manifest', terminalGraph.missing_statements?.includes('manifest') === true);
ok('terminal-only never pass on portal incomplete graph', terminalGraph.verdict !== 'pass');

const digestGraph = evaluateCompositeEvidenceGraph(digestOnly, digestMeta.profile);
expectVerdict('digest-only carrier profile', digestGraph, digestMeta.expected_verdict);
ok('digest-only missing member_receipts', digestGraph.missing_statements?.includes('member_receipts') === true);
ok('digest-only not carrier_review_ready', digestGraph.policy_checks?.carrier_review_ready !== true);

const mgaGraph = evaluateCompositeEvidenceGraph(mgaHashOnly, mgaMeta.profile);
expectVerdict('MGA exporter verify_ok without body', mgaGraph, mgaMeta.expected_verdict);
ok('MGA hash-only missing member_proof_layer', mgaGraph.missing_statements?.includes('member_proof_layer') === true);
ok('MGA exporter graph never pass closed-world', mgaGraph.verdict !== 'pass');

console.log('\n--- PC-09 exporter verify_ok without re-verify (INV-03) ---\n');

const mgaVerify = verifyCarrierMgaAcceptanceKit(mgaHashOnly);
ok('MGA kit verify fails closed without proof layer', mgaVerify.ok === false);
ok(
  'MGA kit note cites proof path',
  String(mgaVerify.note || '').includes('member_verify_attestations') ||
    String(mgaVerify.note || '').includes('member_documents'),
);
ok(
  'composed_members still claim verify_ok (attack surface)',
  mgaHashOnly.composed_members.every((m) => m.verify_ok === true),
);

console.log('\n--- Cross-check: carrier profile on terminal-only must not pass ---\n');

const terminalCarrier = evaluateCompositeEvidenceGraph(terminalOnly, 'carrier_handoff_closed_world');
ok('terminal-only carrier profile not pass', terminalCarrier.verdict !== 'pass');

console.log(`\nLane 4 composite mutators: ${passed} checks passed.\n`);
