#!/usr/bin/env node
/**
 * isRecord public export smoke (@aevesa/verify + @aevesa/shared re-export).
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isRecord } from '../dist/index.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../..');
const sharedBuild = spawnSync('npm', ['run', 'build', '--workspace=@aevesa/shared'], {
  cwd: repoRoot,
  stdio: 'inherit',
});
if (sharedBuild.status !== 0) {
  process.exit(sharedBuild.status ?? 1);
}

const { isRecord: isRecordShared } = await import('../../shared/dist/index.js');

for (const fn of [isRecord, isRecordShared]) {
  if (typeof fn !== 'function') {
    console.error('isRecord is not a function');
    process.exit(1);
  }
  if (!fn({ a: 1 })) {
    console.error('isRecord({}) expected true');
    process.exit(1);
  }
  if (fn(null) || fn([]) || fn('x')) {
    console.error('isRecord rejected valid negative cases');
    process.exit(1);
  }
}

console.log('isRecord export OK (verify + shared)');
