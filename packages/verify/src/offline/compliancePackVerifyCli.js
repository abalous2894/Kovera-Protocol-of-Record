/**
 * Offline compliance pack ZIP verifier — file_integrity + optional manifest.sig (HMAC-SHA256).
 * Bundled into pack ZIP exports via scripts/compliance-pack/generate-verify-script.mjs.
 */

import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { sha256Utf8 } from '../core/sha256.js';
import { verifyConformityPackManifestSignature } from '../core/art12Manifest.js';

/**
 * @typedef {'signed-pack' | 'integrity-only'} CompliancePackVerifyProfile
 */

/**
 * @param {string} rootDir
 * @param {{ profile?: CompliancePackVerifyProfile, verboseIntegrity?: boolean }} [opts]
 * @returns {{ ok: boolean }}
 */
export function runCompliancePackVerify(rootDir, opts = {}) {
  const profile = opts.profile || 'signed-pack';
  const verboseIntegrity = opts.verboseIntegrity !== false;
  const root = rootDir || process.cwd();
  let ok = true;

  const manifestPath = path.join(root, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const integrity = manifest.file_integrity || {};
  const skipIntegritySelf = new Set(['manifest.json', 'manifest.sig']);

  for (const [rel, expected] of Object.entries(integrity)) {
    if (skipIntegritySelf.has(rel)) continue;
    const full = path.join(root, rel);
    const hash = sha256Utf8(readFileSync(full, 'utf8'));
    if (hash !== expected) {
      ok = false;
      if (verboseIntegrity) {
        console.error('FAIL', rel, 'expected', expected, 'got', hash);
      } else {
        console.error('FAIL', rel);
      }
    } else {
      console.log('OK', rel);
    }
  }

  if (profile === 'signed-pack') {
    const sigPath = path.join(root, 'manifest.sig');
    if (existsSync(sigPath)) {
      const sig = JSON.parse(readFileSync(sigPath, 'utf8'));
      const secret = process.env.COMPLIANCE_PACK_SIGNING_SECRET || '';
      if (!secret) {
        console.warn('SKIP manifest.sig — set COMPLIANCE_PACK_SIGNING_SECRET to verify signature');
      } else {
        const result = verifyConformityPackManifestSignature(manifest, sig, secret);
        if (!result.ok) {
          ok = false;
          console.error('FAIL manifest.sig', result.reason || 'INVALID');
        } else {
          console.log('OK manifest.sig');
        }
      }
    }
  }

  return { ok };
}
