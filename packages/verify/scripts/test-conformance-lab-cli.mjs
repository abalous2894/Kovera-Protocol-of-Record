#!/usr/bin/env node
/**
 * Conformance Lab CLI smoke test — local interop, mock remote probe, attestation verify.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  runLocalConformanceInterop,
  probeDeploymentConformance,
  runConformanceLab,
} from '../src/conformance/runConformanceLab.js';
import {
  buildConformanceAttestation,
  verifyConformanceAttestation,
  computeConformanceAttestationDigest,
} from '../src/conformance/conformanceAttestation.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const fixture = join(root, 'fixtures/conformance-local-interop.json');
const cli = join(root, 'src/cli.js');

const local = runLocalConformanceInterop(fixture);
assert.equal(local.ok, true, 'local interop should pass');
assert.equal(local.steps.every((s) => s.ok), true);
assert.match(String(local.entry_hash), /^[a-f0-9]{64}$/);

const attestationBody = buildConformanceAttestation({
  apiBase: null,
  programs: [{ id: 'local-interop/v1', ok: true }],
  interop: { entry_hash: local.entry_hash, local },
});
assert.equal(attestationBody.schema, 'aevesa.conformance-attestation/v1');
assert.match(attestationBody.attestation_digest, /^[a-f0-9]{64}$/);
assert.equal(
  computeConformanceAttestationDigest(attestationBody),
  attestationBody.attestation_digest,
);

const verifyGood = verifyConformanceAttestation(attestationBody);
assert.equal(verifyGood.ok, true, verifyGood.errors.join('; '));

const tampered = { ...attestationBody, ok: false };
assert.equal(verifyConformanceAttestation(tampered).ok, false);

const originalFetch = globalThis.fetch;
const mockBase = 'https://mock-api.aevesa.test';
globalThis.fetch = async (url) => {
  const u = String(url);
  if (u === `${mockBase}/health`) {
    return new Response(JSON.stringify({ ok: true, status: 'healthy' }), { status: 200 });
  }
  if (u === `${mockBase}/api/v1/public/evidence/spec`) {
    return new Response(
      JSON.stringify({
        ok: true,
        conformancePrograms: [{ id: 'a' }, { id: 'b' }, { id: 'c' }],
      }),
      { status: 200 },
    );
  }
  if (u === `${mockBase}/api/v1/public/evidence/conformance-lab-demo`) {
    return new Response(
      JSON.stringify({
        ok: true,
        conformance_programs: [
          { id: 'gateway-attest/v1', program: 'gateway-attest/v1', test: 't' },
          { id: 'receipt-verify/v1', program: 'receipt-verify/v1', test: 't' },
          { id: 'offline-interop/v1', program: 'offline-interop/v1', test: 't' },
        ],
        interop: {
          entry_hash: local.entry_hash,
          within_target: true,
        },
      }),
      { status: 200 },
    );
  }
  return new Response('not found', { status: 404 });
};

try {
  const remote = await probeDeploymentConformance(mockBase);
  assert.equal(remote.ok, true, JSON.stringify(remote.checks));
  assert.equal(remote.checks.length, 3);

  const full = await runConformanceLab({ apiBase: mockBase, fixturePath: fixture });
  assert.equal(full.ok, true);
  assert.equal(full.programs.length, 4);
  assert.equal(verifyConformanceAttestation(full).ok, true);
} finally {
  globalThis.fetch = originalFetch;
}

const tmp = mkdtempSync(join(tmpdir(), 'aevesa-conformance-'));
const outPath = join(tmp, 'attestation.json');

const localRun = spawnSync(
  process.execPath,
  [cli, 'conformance', 'run', '--local-only', '--fixture', fixture, '--output', outPath, '--summary'],
  { encoding: 'utf8' },
);
assert.equal(localRun.status, 0, localRun.stderr || localRun.stdout);
assert.match(localRun.stdout, /aevesa conformance lab attestation/);
assert.match(localRun.stdout, /\[PASS\] local-interop/);

const written = JSON.parse(readFileSync(outPath, 'utf8'));
assert.equal(written.ok, true);
assert.equal(verifyConformanceAttestation(written).ok, true);

const verifyRun = spawnSync(process.execPath, [cli, 'conformance', 'verify', outPath, '--summary'], {
  encoding: 'utf8',
});
assert.equal(verifyRun.status, 0, verifyRun.stderr || verifyRun.stdout);
assert.match(verifyRun.stdout, /attestation verify/);

console.log('conformance lab CLI smoke OK');
