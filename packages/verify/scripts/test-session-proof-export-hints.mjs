#!/usr/bin/env node
/**
 * Phase 2 — session proof export hints (requireMemberReceiptVerification).
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const verifyPkg = join(__dirname, '..');

let passed = 0;
function ok(label, cond) {
  assert.equal(cond, true, label);
  passed += 1;
  console.log(`  ✓ ${label}`);
}

console.log('\nSession proof export hints — conformance\n');

const build = spawnSync('npm', ['run', 'build'], { cwd: verifyPkg, stdio: 'inherit' });
ok('build succeeded', build.status === 0);

const { buildSessionProofExportHints } = await import('@aevesa/verify');

const manifestOnly = buildSessionProofExportHints({ declared_count: 4, member_receipts: [] });
ok('manifest-only requires member verification', manifestOnly.require_member_receipt_verification === true);
ok('manifest-only note present', manifestOnly.notes.length > 0);

const bundled = buildSessionProofExportHints({
  declared_count: 2,
  member_receipts: [{ schema: 'liability-receipt/v1' }, { schema: 'liability-receipt/v1' }],
});
ok('bundled members ok', bundled.member_receipts_bundled === true);
ok('bundled no require flag', bundled.require_member_receipt_verification === false);

console.log(`\n${passed} checks passed.\n`);
