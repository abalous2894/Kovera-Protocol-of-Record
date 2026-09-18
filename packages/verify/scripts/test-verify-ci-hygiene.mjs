#!/usr/bin/env node
/**
 * Wave 15 Track D — verify-ci install hygiene (vitest resolution + scripts-only entry).
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveVitestCliPath } from './run-vitest.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(__dirname, '..');
const pkgJson = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf8'));

assert.ok(pkgJson.scripts['test:verify-ci:scripts-only'], 'test:verify-ci:scripts-only script present');
assert.match(pkgJson.scripts['test:unit'], /run-vitest\.mjs/, 'test:unit uses run-vitest.mjs');
assert.match(pkgJson.scripts['test:unit:coverage'], /run-vitest\.mjs/, 'test:unit:coverage uses run-vitest.mjs');

const vitestCli = resolveVitestCliPath();
assert.ok(vitestCli, 'vitest CLI resolves after workspace install');

const unitRun = spawnSync(process.execPath, [join(__dirname, 'run-vitest.mjs'), 'run'], {
  cwd: pkgRoot,
  encoding: 'utf8',
});
assert.equal(unitRun.status, 0, unitRun.stderr || unitRun.stdout);

console.log('verify-ci install hygiene OK');
