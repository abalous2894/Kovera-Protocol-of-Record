#!/usr/bin/env node
/**
 * Phase B — GitHub Action smoke test (local composite action via verify.sh).
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const repoRoot = join(root, '..', '..');
const verifySh = join(repoRoot, '.github/actions/verify/verify.sh');
const fixture = join(root, 'fixtures/policy-proof-deny-bundle.json');

assert.ok(existsSync(verifySh), 'verify.sh exists');

function runAction(extraEnv = {}) {
  return spawnSync('bash', [verifySh], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      INPUT_PATH: fixture,
      INPUT_WORKING_DIRECTORY: 'packages/verify',
      INPUT_SUMMARY: 'true',
      INPUT_JSON: 'false',
      INPUT_NO_FETCH: 'true',
      ...extraEnv,
    },
  });
}

const passRun = runAction();
assert.equal(passRun.status, 0, passRun.stderr || passRun.stdout);
assert.match(passRun.stdout, /aevesa verify/);
assert.match(passRun.stdout, /DENIED_VALID/);

const jsonPath = join(repoRoot, 'aevesa-verify-action-test-report.json');
const jsonRun = runAction({
  INPUT_JSON: 'true',
  INPUT_REPORT_PATH: jsonPath,
  INPUT_SUMMARY: 'false',
});
assert.equal(jsonRun.status, 0, jsonRun.stderr);
assert.ok(existsSync(jsonPath), 'report written');
const report = JSON.parse(readFileSync(jsonPath, 'utf8'));
assert.equal(report.schema, 'aevesa.verification-report/v1');
assert.equal(report.ok, true);

console.log('verify GitHub Action smoke OK');
