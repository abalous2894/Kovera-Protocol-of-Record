#!/usr/bin/env node
/**
 * Phase 4 — chain-enforcement rollup open conformance lab (repo wiring smoke).
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../../..');

const lab = spawnSync('node', [
  'diligence-kit/samples/conformance-lab/chain-enforcement-rollup/run-lab.mjs',
], {
  cwd: repoRoot,
  stdio: 'inherit',
});
if (lab.status !== 0) process.exit(lab.status ?? 1);

const profile = readFileSync(
  join(repoRoot, 'docs/standards/CHAIN_ENFORCEMENT_ROLLUP_PROFILE.md'),
  'utf8',
);
if (!profile.includes('rollupChainEnforcement')) {
  console.error('profile doc missing rollupChainEnforcement');
  process.exit(1);
}

const spec = readFileSync(join(repoRoot, 'spec/aevesa-chain-enforcement-rollup-v1.json'), 'utf8');
if (!spec.includes('aevesa.chain-enforcement-rollup/v1')) {
  console.error('open spec missing schema const');
  process.exit(1);
}

const { runChainEnforcementRollupConformanceLab } = await import(
  '../src/conformance/chainEnforcementRollupConformanceLab.js'
);
const rollupAttestationSlice = runChainEnforcementRollupConformanceLab({ repoRoot });
if (!rollupAttestationSlice.ok) {
  console.error('rollup attestation slice failed', rollupAttestationSlice);
  process.exit(1);
}

const sampleAttestation = readFileSync(
  join(repoRoot, 'conformance-lab/attestation/sample-attestation.json'),
  'utf8',
);
if (!sampleAttestation.includes('chain-enforcement-rollup/v1')) {
  console.error('sample attestation missing chain-enforcement-rollup program');
  process.exit(1);
}

console.log('chain-enforcement conformance lab wiring OK');
