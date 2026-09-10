#!/usr/bin/env node
/**
 * Unified aevesa verify CLI smoke test.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { detectEvidenceType } from '../src/verify/detectEvidenceType.js';
import { runUnifiedVerify } from '../src/verify/runUnifiedVerify.js';
import { buildAuditorPacket, verifyAuditorPacket } from '../src/verify/buildAuditorPacket.js';
import { buildAuditorPacket as buildAuditorPacketDist, verifyAuditorPacket as verifyAuditorPacketDist } from '../dist/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const cli = join(root, 'src/cli.js');

const policyProof = JSON.parse(
  readFileSync(join(root, 'fixtures/policy-proof-deny-bundle.json'), 'utf8'),
);
const replayBundle = JSON.parse(readFileSync(join(root, 'fixtures/replay-sample-bundle.json'), 'utf8'));

assert.equal(detectEvidenceType(policyProof).kind, 'policy_proof_bundle');
assert.equal(detectEvidenceType(replayBundle).kind, 'proof_of_action_bundle');
assert.equal(detectEvidenceType(policyProof.receipt).kind, 'liability_receipt');

const policyReport = await runUnifiedVerify(policyProof, { fetch: false });
assert.equal(policyReport.ok, true, policyReport.errors?.join('; '));
assert.equal(policyReport.verdict, 'DENIED_VALID');
assert.equal(policyReport.schema, 'aevesa.verification-report/v1');

const replayReport = await runUnifiedVerify(replayBundle, { fetch: false });
assert.equal(replayReport.ok, true, replayReport.errors?.join('; '));
assert.ok(replayReport.replay?.event_count >= 4);

const receiptReport = await runUnifiedVerify(policyProof.receipt, { fetch: false });
assert.equal(receiptReport.ok, true);

const packet = buildAuditorPacket({
  receipt: policyProof.receipt,
  bundle: replayBundle,
  executiveSummary: 'Auditor packet smoke test.',
});
assert.equal(verifyAuditorPacket(packet).ok, true);
const wirePacket = JSON.parse(JSON.stringify(packet));
assert.equal(verifyAuditorPacket(wirePacket).ok, true, 'digest must survive JSON wire round-trip');

const distPacket = buildAuditorPacketDist({
  receipt: policyProof.receipt,
  bundle: replayBundle,
  executiveSummary: 'Auditor packet dist smoke test.',
  generatedAt: packet.generated_at,
});
assert.equal(verifyAuditorPacketDist(distPacket).ok, true, 'dist buildAuditorPacket digest must verify');
assert.equal(
  verifyAuditorPacketDist(JSON.parse(JSON.stringify(distPacket))).ok,
  true,
  'dist digest must survive JSON wire round-trip',
);

const packetReport = await runUnifiedVerify(packet, { fetch: false });
assert.equal(packetReport.ok, true, packetReport.errors?.join('; '));

const summaryRun = spawnSync(
  process.execPath,
  [cli, 'verify', join(root, 'fixtures/policy-proof-deny-bundle.json'), '--summary'],
  { encoding: 'utf8' },
);
assert.equal(summaryRun.status, 0, summaryRun.stderr || summaryRun.stdout);
assert.match(summaryRun.stdout, /aevesa verify/);
assert.match(summaryRun.stdout, /DENIED_VALID/);

const jsonRun = spawnSync(
  process.execPath,
  [cli, 'verify', join(root, 'fixtures/replay-sample-bundle.json'), '--json'],
  { encoding: 'utf8' },
);
assert.equal(jsonRun.status, 0, jsonRun.stderr);
const parsed = JSON.parse(jsonRun.stdout);
assert.equal(parsed.evidence_kind, 'proof_of_action_bundle');

console.log('unified verify CLI smoke OK');
