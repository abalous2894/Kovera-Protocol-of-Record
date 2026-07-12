/**
 * Art. 12 Conformity Pack manifest signing — identical to art12PackSigningService.js.
 */

import { createHmac, createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const COMPLIANCE_PACK_SIGNING_KEY_ID = 'aevesa-compliance-pack-signing-v1';

/** Spec golden-vector secret (§6.6). */
export const SPEC_TEST_VECTOR_SIGNING_SECRET = 'spec-test-vector-secret-v1';

/**
 * @returns {string}
 */
export function getCompliancePackSigningSecret() {
  const secret = process.env.COMPLIANCE_PACK_SIGNING_SECRET;
  if (!secret || !String(secret).trim()) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('COMPLIANCE_PACK_SIGNING_SECRET is required in production');
    }
    return 'dev-compliance-pack-signing-not-for-production';
  }
  return String(secret).trim();
}

/**
 * @param {Record<string, unknown>} manifest
 */
export function manifestPayloadForSigning(manifest) {
  const copy = JSON.parse(JSON.stringify(manifest));
  if (copy.file_integrity && typeof copy.file_integrity === 'object') {
    const fi = { ...copy.file_integrity };
    delete fi['manifest.sig'];
    delete fi['manifest.json'];
    copy.file_integrity = fi;
  }
  return copy;
}

/**
 * @param {Record<string, unknown>} manifest
 */
export function hashManifestForSigning(manifest) {
  return createHash('sha256').update(stableStringify(manifestPayloadForSigning(manifest)), 'utf8').digest('hex');
}

/**
 * @param {Record<string, unknown>} manifest
 * @param {string} [secret]
 * @param {{ signedAt?: string }} [opts]
 */
export function signConformityPackManifest(manifest, secret = getCompliancePackSigningSecret(), opts = {}) {
  const manifestSha256 = hashManifestForSigning(manifest);
  const signature = createHmac('sha256', secret).update(manifestSha256, 'utf8').digest('base64');
  const signedAt =
    opts.signedAt ||
    process.env.AEVESA_PACK_DETERMINISTIC_SIGNED_AT?.trim() ||
    new Date().toISOString();

  return {
    algorithm: 'HMAC-SHA256',
    manifestSha256,
    signedAt,
    keyId: COMPLIANCE_PACK_SIGNING_KEY_ID,
    signature,
  };
}

/**
 * @param {Record<string, unknown>} manifest
 * @param {{ algorithm?: string, manifestSha256?: string, signature?: string }} sigEnvelope
 * @param {string} [secret]
 */
export function verifyConformityPackManifestSignature(manifest, sigEnvelope, secret = getCompliancePackSigningSecret()) {
  if (!sigEnvelope || sigEnvelope.algorithm !== 'HMAC-SHA256') {
    return { ok: false, reason: 'UNSUPPORTED_ALGORITHM' };
  }
  const expectedHash = hashManifestForSigning(manifest);
  if (String(sigEnvelope.manifestSha256 || '').toLowerCase() !== expectedHash) {
    return { ok: false, reason: 'MANIFEST_HASH_MISMATCH' };
  }
  const expectedSig = createHmac('sha256', secret).update(expectedHash, 'utf8').digest('base64');
  if (String(sigEnvelope.signature || '') !== expectedSig) {
    return { ok: false, reason: 'SIGNATURE_MISMATCH' };
  }
  return { ok: true, reason: null, manifestSha256: expectedHash };
}
