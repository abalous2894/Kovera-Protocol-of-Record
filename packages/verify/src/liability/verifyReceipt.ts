import type { VerificationResult } from './types.js';
import { computeReceiptDigest } from './digest.js';
import { parseLiabilityReceiptStructure } from './schema.js';
import { verifyAnchorHashChain, verifyPolicyVersionHash } from './anchors.js';
import { verifyIntegritySignatures } from './signatures.js';
import { validateAccountabilityPillars } from './pillars.js';

export interface VerifyReceiptOptions {
  /** SPKI PEM or JWK JSON — required for Ed25519/RS256 when signature is present */
  issuerPublicKey?: string | Buffer;
  /** When true, enforce policy_version_hash === sha256(policy_pack_id) */
  strictPolicyVersionHash?: boolean;
}

/**
 * Stateless verification for liability-receipt/v1:
 * 1. Structural schema (Zod)
 * 2. receipt_digest preimage (SHA-256 canonical pillars)
 * 3. Anchor hash-chain / format
 * 4. Signature block
 * 5. Cross-pillar accountability rules
 */
export function verifyReceipt(receiptData: unknown, options: VerifyReceiptOptions = {}): VerificationResult {
  if (receiptData == null || typeof receiptData !== 'object' || Array.isArray(receiptData)) {
    return { isValid: false, error: 'Receipt must be a JSON object' };
  }

  const structural = parseLiabilityReceiptStructure(receiptData);
  if (!structural.ok) {
    return { isValid: false, error: structural.error };
  }

  const receipt = structural.receipt;
  const pillars = validateAccountabilityPillars(receipt);
  if (!pillars.ok) {
    return {
      isValid: false,
      error: pillars.error,
      details: { chainLength: 0, pillarsValidated: pillars.pillarsValidated },
    };
  }

  const recomputed = computeReceiptDigest(receipt as unknown as Record<string, unknown>);
  if (recomputed !== receipt.integrity.receipt_digest) {
    return {
      isValid: false,
      error: 'integrity.receipt_digest mismatch — document preimage was altered after sealing',
      details: {
        chainLength: 1 + (receipt.proof.secondary_anchors?.length ?? 0),
        pillarsValidated: pillars.pillarsValidated,
      },
    };
  }

  const anchors = verifyAnchorHashChain(receipt);
  if (!anchors.ok) {
    return {
      isValid: false,
      error: anchors.error,
      details: { chainLength: anchors.chainLength, pillarsValidated: pillars.pillarsValidated },
    };
  }

  if (options.strictPolicyVersionHash !== false) {
    const policyHash = verifyPolicyVersionHash(receipt);
    if (!policyHash.ok) {
      return {
        isValid: false,
        error: policyHash.error,
        details: { chainLength: anchors.chainLength, pillarsValidated: pillars.pillarsValidated },
      };
    }
  }

  const sig = verifyIntegritySignatures(receipt, options.issuerPublicKey);
  if (!sig.ok) {
    return {
      isValid: false,
      error: sig.error,
      details: { chainLength: anchors.chainLength, pillarsValidated: pillars.pillarsValidated },
    };
  }

  return {
    isValid: true,
    details: {
      chainLength: anchors.chainLength,
      pillarsValidated: pillars.pillarsValidated,
    },
  };
}
