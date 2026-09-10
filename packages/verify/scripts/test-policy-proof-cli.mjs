#!/usr/bin/env node
/**
 * Policy-proof verify CLI smoke test.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { parseDatalogFacts } from '../src/policy/datalogFactsParser.js';
import { evaluatePathFromFacts } from '../src/policy/evaluatePathFromFacts.js';
import { verifyPolicyProofBundle } from '../src/policy/policyProofVerify.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const fixture = join(root, 'fixtures/policy-proof-deny-bundle.json');
const cli = join(root, 'src/cli.js');

const bundle = JSON.parse(readFileSync(fixture, 'utf8'));
assert.equal(bundle.schema, 'aevesa.policy-proof-bundle/v1');

const parse = parseDatalogFacts(bundle.datalog_export.facts);
assert.equal(parse.ok, true);
assert.equal(parse.parsed?.readCount, 4);

const reeval = evaluatePathFromFacts(parse.parsed, 'export_data', { maxReadsBeforeDestructive: 3 });
assert.equal(reeval.allow, false);
assert.equal(reeval.code, 'PATH_READ_VELOCITY_DESTRUCTIVE');

const result = verifyPolicyProofBundle(bundle);
assert.equal(result.ok, true, result.errors?.join('; '));
assert.equal(result.deny_proven, true);

const tampered = structuredClone(bundle);
tampered.datalog_export.policy_evaluation.allow = true;
assert.equal(verifyPolicyProofBundle(tampered).ok, false);

const summaryRun = spawnSync(process.execPath, [cli, 'policy-proof', fixture, '--summary'], {
  encoding: 'utf8',
});
assert.equal(summaryRun.status, 0, summaryRun.stderr || summaryRun.stdout);
assert.match(summaryRun.stdout, /policy-proof verify/);
assert.match(summaryRun.stdout, /deny_proven:\s+true/);

console.log('policy-proof CLI smoke OK');
