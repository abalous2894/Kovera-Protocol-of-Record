#!/usr/bin/env node
/**
 * Phase C — policy-proof template list/export smoke test.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  exportPolicyProofTemplate,
  loadPolicyProofTemplateIndex,
} from '../src/policy/policyProofTemplates.js';
import { verifyPolicyProofBundle } from '../src/policy/policyProofVerify.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const cli = join(root, 'src/cli.js');

const index = loadPolicyProofTemplateIndex();
assert.equal(index.schema, 'aevesa.policy-proof-templates/v1');
assert.ok(index.templates.some((t) => t.id === 'read-chain-export-deny'));

const dir = mkdtempSync(join(tmpdir(), 'aevesa-ppt-'));
const exportDir = mkdtempSync(join(tmpdir(), 'aevesa-ppt-export-'));
try {
  const exported = exportPolicyProofTemplate('read-chain-export-deny', dir);
  assert.equal(exported.ok, true);
  const bundle = JSON.parse(readFileSync(join(dir, 'bundle.json'), 'utf8'));
  assert.equal(bundle.schema, 'aevesa.policy-proof-bundle/v1');
  const verify = verifyPolicyProofBundle(bundle);
  assert.equal(verify.ok, true, verify.errors?.join('; '));
} finally {
  rmSync(dir, { recursive: true, force: true });
}

const listRun = spawnSync(process.execPath, [cli, 'policy-proof', 'template', 'list'], { encoding: 'utf8' });
assert.equal(listRun.status, 0, listRun.stderr);
assert.match(listRun.stdout, /read-chain-export-deny/);

const exportRun = spawnSync(
  process.execPath,
  [cli, 'policy-proof', 'template', 'export', 'read-chain-export-deny', '--output', exportDir],
  { encoding: 'utf8' },
);
assert.equal(exportRun.status, 0, exportRun.stderr);
rmSync(exportDir, { recursive: true, force: true });

console.log('policy-proof template smoke OK');
