#!/usr/bin/env node
/**
 * Fail CI when sentinul-app-site verify bundle is stale vs @aevesa/verify build.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const verifyPkgDir = join(scriptDir, '..');
const repoRoot = join(verifyPkgDir, '../..');
const committedPath = join(repoRoot, 'sentinul-app-site/src/js/aevesa-verify.bundle.js');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkgDir, stdio: 'inherit' });
if (build.status !== 0) {
  process.exit(build.status ?? 1);
}

const tmpDir = mkdtempSync(join(tmpdir(), 'aevesa-verify-bundle-check-'));
const tmpOut = join(tmpDir, 'aevesa-verify.bundle.js');

const bundle = spawnSync('node', ['scripts/build-browser-bundle.mjs'], {
  cwd: verifyPkgDir,
  env: { ...process.env, AEVESA_VERIFY_BUNDLE_OUTFILE: tmpOut },
  stdio: 'inherit',
});

try {
  if (bundle.status !== 0) {
    process.exit(bundle.status ?? 1);
  }

  const committed = readFileSync(committedPath);
  const fresh = readFileSync(tmpOut);
  if (committed.length !== fresh.length || !committed.equals(fresh)) {
    console.error('Error: aevesa-verify.bundle.js is out of sync with @aevesa/verify.');
    console.error('Run: npm run build:browser --workspace=@aevesa/verify');
    console.error('Then commit sentinul-app-site/src/js/aevesa-verify.bundle.js');
    process.exit(1);
  }

  console.log('OK verify browser bundle in sync');
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}
