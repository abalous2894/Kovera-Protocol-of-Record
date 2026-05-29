import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { ParsedLiabilityReceipt } from './schema.js';
import { computeReceiptDigest } from './digest.js';

export interface SignatureVerifyResult {
  ok: boolean;
  error?: string;
}

function decodeBase64Url(input: string): Buffer {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
  return Buffer.from(padded + pad, 'base64');
}

/**
 * Verify integrity.signature / manifest_signature_jws without network or DB.
 * Ed25519/RS256 require `issuerPublicKey` (SPKI PEM or JWK JSON string) when alg is not `none`.
 */
export function verifyIntegritySignatures(
  receipt: ParsedLiabilityReceipt,
  issuerPublicKey?: string | Buffer,
): SignatureVerifyResult {
  const { integrity } = receipt;
  const alg = integrity.signature_alg;

  if (alg === 'none') {
    if (integrity.signature != null && String(integrity.signature).length > 0) {
      return { ok: false, error: 'integrity.signature must be null when signature_alg is none' };
    }
    if (integrity.manifest_signature_jws != null && String(integrity.manifest_signature_jws).length > 0) {
      return {
        ok: false,
        error: 'integrity.manifest_signature_jws must be null when signature_alg is none',
      };
    }
    return { ok: true };
  }

  const digestPayload = computeReceiptDigest(receipt as unknown as Record<string, unknown>);
  const message = Buffer.from(digestPayload, 'utf8');

  if (alg === 'Ed25519') {
    if (!integrity.signature) {
      return { ok: false, error: 'integrity.signature required for Ed25519' };
    }
    if (!issuerPublicKey) {
      return {
        ok: false,
        error:
          'Ed25519 verification requires issuer public key (pass via verifyReceipt options in a future revision or embed in receipt)',
      };
    }
    try {
      const sig = Buffer.from(integrity.signature, 'base64');
      const key =
        typeof issuerPublicKey === 'string'
          ? createPublicKey(issuerPublicKey.trim().startsWith('{') ? { key: issuerPublicKey, format: 'jwk' } : issuerPublicKey)
          : createPublicKey(issuerPublicKey);
      const ok = cryptoVerify(null, message, key, sig);
      return ok ? { ok: true } : { ok: false, error: 'Ed25519 signature mismatch over receipt_digest preimage' };
    } catch (e) {
      return { ok: false, error: `Ed25519 verify failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  }

  if (alg === 'RS256') {
    const jws = integrity.manifest_signature_jws ?? integrity.signature;
    if (!jws || typeof jws !== 'string') {
      return { ok: false, error: 'RS256 requires manifest_signature_jws or integrity.signature JWS' };
    }
    const parts = jws.split('.');
    if (parts.length !== 3) {
      return { ok: false, error: 'Invalid JWS compact serialization' };
    }
    if (!issuerPublicKey) {
      return { ok: false, error: 'RS256 JWS verification requires issuer public key' };
    }
    try {
      const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
      const sig = decodeBase64Url(parts[2]);
      const key =
        typeof issuerPublicKey === 'string'
          ? createPublicKey(issuerPublicKey.trim().startsWith('{') ? { key: issuerPublicKey, format: 'jwk' } : issuerPublicKey)
          : createPublicKey(issuerPublicKey);
      const ok = cryptoVerify('RSA-SHA256', signingInput, key, sig);
      if (!ok) {
        return { ok: false, error: 'RS256 JWS signature mismatch' };
      }
      const payloadJson = decodeBase64Url(parts[1]).toString('utf8');
      const payload = JSON.parse(payloadJson) as { receipt_digest?: string };
      if (payload.receipt_digest && payload.receipt_digest !== integrity.receipt_digest) {
        return { ok: false, error: 'JWS payload receipt_digest does not match integrity.receipt_digest' };
      }
      return { ok: true };
    } catch (e) {
      return { ok: false, error: `RS256 verify failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  }

  return { ok: false, error: `Unsupported signature_alg: ${alg}` };
}
