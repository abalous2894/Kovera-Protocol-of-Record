#!/usr/bin/env node
/**
 * Offline replay-bundle CLI smoke test.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { replayProofBundle } from '../src/replay/replayProofBundle.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const fixture = join(root, 'fixtures/replay-sample-bundle.json');
const cli = join(root, 'src/cli.js');

const bundle = JSON.parse(readFileSync(fixture, 'utf8'));
const replay = replayProofBundle(bundle);

assert.equal(replay.schema, 'aevesa.session-replay/v1');
assert.equal(replay.offline, true);
assert.ok(replay.event_count >= 4, 'expected anchor + intent + witness + forensic hops');
assert.ok(replay.timeline.some((e) => e.kind === 'ledger_anchor'));
assert.ok(replay.timeline.some((e) => e.kind === 'forensic_hop'));
assert.equal(replay.hop_count, 2);

const summaryRun = spawnSync(process.execPath, [cli, 'replay-bundle', fixture, '--summary'], {
  encoding: 'utf8',
});
assert.equal(summaryRun.status, 0, summaryRun.stderr || summaryRun.stdout);
assert.match(summaryRun.stdout, /aevesa session replay/);
assert.match(summaryRun.stdout, /forensic_hop/);

const jsonRun = spawnSync(process.execPath, [cli, 'replay-bundle', fixture, '--json'], {
  encoding: 'utf8',
});
assert.equal(jsonRun.status, 0, jsonRun.stderr);
const parsed = JSON.parse(jsonRun.stdout);
assert.equal(parsed.entry_hash, bundle.manifest.entry_hash);

console.log('replay-bundle CLI smoke OK');
