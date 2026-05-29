/**
 * Offline Art. 12 Conformity Pack verification — manifest signature + file_integrity.
 * Reference: kovera-sovereign-ledger-spec.md §6.4
 */

import fs from 'node:fs';
import path from 'node:path';
import { sha256Buffer } from './sha256.js';
import { verifyConformityPackManifestSignature, getCompliancePackSigningSecret } from './art12Manifest.js';
import { readZipEntriesFromFile } from './readZip.js';

/**
 * @param {Map<string, Buffer> | Record<string, Buffer>} files
 * @param {{ secret?: string, requireSignature?: boolean }} [opts]
 */
export function verifyArt12PackFiles(files, opts = {}) {
  const fileMap = files instanceof Map ? files : new Map(Object.entries(files));

  const manifestBuf = fileMap.get('manifest.json');
  if (!manifestBuf) {
    return { ok: false, reason: 'MISSING_MANIFEST', detail: 'manifest.json not found' };
  }

  let manifest;
  try {
    manifest = JSON.parse(manifestBuf.toString('utf8'));
  } catch (e) {
    return { ok: false, reason: 'INVALID_MANIFEST_JSON', detail: e.message };
  }

  /** @type {Array<{ step: string, pass: boolean, detail: string }>} */
  const layers = [];

  const sigBuf = fileMap.get('manifest.sig');
  if (!sigBuf) {
    if (opts.requireSignature !== false) {
      return { ok: false, reason: 'MISSING_MANIFEST_SIG', detail: 'manifest.sig not found' };
    }
  } else {
    let sigEnvelope;
    try {
      sigEnvelope = JSON.parse(sigBuf.toString('utf8'));
    } catch (e) {
      return { ok: false, reason: 'INVALID_MANIFEST_SIG_JSON', detail: e.message };
    }

    const secret = opts.secret ?? getCompliancePackSigningSecret();
    if (!secret) {
      return {
        ok: false,
        reason: 'MISSING_SIGNING_SECRET',
        detail: 'Set COMPLIANCE_PACK_SIGNING_SECRET to verify manifest.sig',
      };
    }

    const sigResult = verifyConformityPackManifestSignature(manifest, sigEnvelope, secret);
    layers.push({
      step: 'manifest.sig',
      pass: sigResult.ok,
      detail: sigResult.ok ? 'manifest signature verified' : `signature failed: ${sigResult.reason}`,
    });
  }

  const integrity = manifest.file_integrity && typeof manifest.file_integrity === 'object' ? manifest.file_integrity : {};
  for (const [rel, expected] of Object.entries(integrity)) {
    const buf = fileMap.get(rel);
    if (!buf) {
      layers.push({ step: `file_integrity[${rel}]`, pass: false, detail: 'file missing in archive' });
      continue;
    }
    const actual = sha256Buffer(buf);
    const pass = String(actual).toLowerCase() === String(expected).toLowerCase();
    layers.push({
      step: `file_integrity[${rel}]`,
      pass,
      detail: pass ? 'hash match' : `expected ${expected} actual ${actual}`,
    });
  }

  const ok = layers.length > 0 && layers.every((l) => l.pass);
  return { ok, reason: ok ? null : 'INTEGRITY_FAILED', manifest, layers };
}

/**
 * @param {string} packPath — path to .zip or extracted directory
 * @param {{ secret?: string }} [opts]
 */
export function verifyArt12PackPath(packPath, opts = {}) {
  const stat = fs.statSync(packPath);
  if (stat.isDirectory()) {
    return verifyArt12PackDirectory(packPath, opts);
  }
  if (stat.isFile() && packPath.toLowerCase().endsWith('.zip')) {
    const entries = readZipEntriesFromFile(packPath, fs.readFileSync);
    return verifyArt12PackFiles(entries, opts);
  }
  return { ok: false, reason: 'UNSUPPORTED_PATH', detail: 'Expected .zip file or extracted directory' };
}

/**
 * @param {string} rootDir
 * @param {{ secret?: string }} [opts]
 */
export function verifyArt12PackDirectory(rootDir, opts = {}) {
  /** @type {Map<string, Buffer>} */
  const files = new Map();

  function walk(current, relPrefix = '') {
    for (const name of fs.readdirSync(current)) {
      const full = path.join(current, name);
      const rel = relPrefix ? `${relPrefix}/${name}` : name;
      const st = fs.statSync(full);
      if (st.isDirectory()) {
        walk(full, rel);
      } else {
        files.set(rel.replace(/\\/g, '/'), fs.readFileSync(full));
      }
    }
  }

  walk(rootDir);
  return verifyArt12PackFiles(files, opts);
}
