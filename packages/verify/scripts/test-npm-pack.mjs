#!/usr/bin/env node
/**
 * Smoke test: npm pack tarball installs and `aevesa verify` runs offline.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(__dirname, '..');
const gatewayReceipt = join(
  pkgRoot,
  '../../aevesa-dashboard/public/demo/gateway-receipt.json',
);

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', ...opts });
  if (r.status !== 0) {
    throw new Error(
      `${cmd} ${args.join(' ')} failed (${r.status}):\n${r.stderr || r.stdout}`,
    );
  }
  return r.stdout;
}

const packOut = run('npm', ['pack', '--silent'], { cwd: pkgRoot }).trim();
const tgz = join(pkgRoot, packOut.split('\n').pop());

const installDir = mkdtempSync(join(tmpdir(), 'aevesa-verify-pack-'));
try {
  run('npm', ['init', '-y'], { cwd: installDir, stdio: 'ignore' });
  run('npm', ['install', tgz], { cwd: installDir });

  const help = run('npx', ['aevesa', 'verify', '--help'], { cwd: installDir });
  assert.match(help, /Unified offline verify/);

  const summary = run(
    'npx',
    ['aevesa', 'verify', gatewayReceipt, '--summary'],
    { cwd: installDir },
  );
  assert.match(summary, /ok:\s+true|DENIED_VALID|VERIFIED/i);

  const npxEntry = run(
    'npx',
    ['verify', 'verify', gatewayReceipt, '--summary'],
    { cwd: installDir },
  );
  assert.match(npxEntry, /ok:\s+true|DENIED_VALID|VERIFIED/i);
  console.log('npm pack smoke OK — aevesa verify + npx verify bin run from installed tarball');
} finally {
  rmSync(installDir, { recursive: true, force: true });
}
