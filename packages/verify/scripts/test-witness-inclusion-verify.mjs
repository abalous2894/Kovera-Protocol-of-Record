#!/usr/bin/env node
/**
 * Witness inclusion + SCITT refusal offline verification smoke test.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  verifyScittRefusalWitnessBundle,
  verifyWitnessInclusionProof,
  calculateWitnessEntryHash,
  WITNESS_GENESIS_HASH,
} from '../src/witness/witnessInclusionVerify.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const cli = join(root, 'src/cli.js');
const fixture = join(root, 'fixtures/scitt-live-witness-export.json');

const exportBundle = JSON.parse(readFileSync(fixture, 'utf8'));
const offline = verifyScittRefusalWitnessBundle(exportBundle);

if (!offline.ok) {
  console.error('verifyScittRefusalWitnessBundle failed', offline);
  process.exit(1);
}

const inclusion = verifyWitnessInclusionProof(
  exportBundle.inclusionProof,
  exportBundle.ledgerAppend,
  exportBundle.verificationExport,
);
if (!inclusion.ok) {
  console.error('verifyWitnessInclusionProof failed', inclusion);
  process.exit(1);
}

const recomputed = calculateWitnessEntryHash(
  {
    orgId: exportBundle.verificationExport.orgId,
    prevHash: exportBundle.verificationExport.prevHash,
    digest: exportBundle.verificationExport.digest,
    eventTimestamp: exportBundle.verificationExport.eventTimestamp,
    nonce: exportBundle.verificationExport.nonce,
    payload: exportBundle.verificationExport.payload,
  },
  exportBundle.ledgerAppend.sequence,
);
if (recomputed !== exportBundle.inclusionProof.root_hash) {
  console.error('hash recompute mismatch', recomputed, exportBundle.inclusionProof.root_hash);
  process.exit(1);
}

if (exportBundle.verificationExport.prevHash !== WITNESS_GENESIS_HASH && exportBundle.ledgerAppend.sequence === 1) {
  // first entry after genesis — parent must be genesis
}

const summaryRun = spawnSync(process.execPath, [cli, 'witness-verify', fixture, '--summary'], {
  encoding: 'utf8',
});
if (summaryRun.status !== 0) {
  console.error(summaryRun.stderr || summaryRun.stdout);
  process.exit(1);
}

console.log('witness inclusion offline verify OK');
