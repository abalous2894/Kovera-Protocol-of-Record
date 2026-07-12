import type { VerificationResult } from './types.js';
import { verifyReceiptDigestMatch } from './digest.js';
import { parseLiabilityReceiptStructure, type ParsedLiabilityReceipt } from './schema.js';
import { verifyAnchorHashChain, verifyPolicyVersionHash } from './anchors.js';
import { verifyIntegritySignatures } from './signatures.js';
import { validateAccountabilityPillars } from './pillars.js';
import { verifyCausalLineageLedgerBinding } from './causalLineageBinding.js';
import { verifyIntentContextLedgerBinding } from './intentContextBinding.js';
import { verifyPartialPathCommitment } from '../core/partialPath.js';

export interface VerifyReceiptOptions {
  /** SPKI PEM or JWK JSON — required for Ed25519/RS256 when signature is present */
  issuerPublicKey?: string | Buffer;
  /** When true, enforce policy_version_hash === sha256(policy_pack_id) */
  strictPolicyVersionHash?: boolean;
  /**
   * Optional persisted aegis/1 row — when intent_context is present, recompute entryHash
   * and confirm governanceBinding includes the same intent_context preimage.
   */
  ledgerDocument?: Record<string, unknown> | null;
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

  if (structural.version === 'v2' && 'privacy' in receipt && receipt.privacy?.shredded_at) {
    return {
      isValid: true,
      details: {
        chainLength: 1 + ((receipt as { proof?: { secondary_anchors?: unknown[] } }).proof?.secondary_anchors?.length ?? 0),
        pillarsValidated: ['privacy_shredded', 'merkle_chain_intact'],
      },
    };
  }

  const receiptV1 = receipt as ParsedLiabilityReceipt;

  const digestCheck = verifyReceiptDigestMatch(receiptData as Record<string, unknown>);
  if (!digestCheck.ok) {
    return {
      isValid: false,
      error:
        'integrity.receipt_digest mismatch — document preimage was altered after sealing (intent_context, intent_alignment, and causal_lineage when present)',
      details: {
        chainLength: 1 + (receiptV1.proof.secondary_anchors?.length ?? 0),
        pillarsValidated: [],
      },
    };
  }

  if (
    digestCheck.profile === 'current' &&
    receiptV1.intent_context &&
    !receiptV1.intent_alignment
  ) {
    return {
      isValid: false,
      error: 'intent_alignment is required when intent_context is present (KVR-102 current digest profile)',
      details: {
        chainLength: 1 + (receiptV1.proof.secondary_anchors?.length ?? 0),
        pillarsValidated: [],
      },
    };
  }

  const pillars = validateAccountabilityPillars(receiptV1);
  if (!pillars.ok) {
    return {
      isValid: false,
      error: pillars.error,
      details: { chainLength: 0, pillarsValidated: pillars.pillarsValidated },
    };
  }

  if (receiptV1.intent_context) {
    const intentBinding = verifyIntentContextLedgerBinding(receiptV1, options.ledgerDocument ?? null);
    if (!intentBinding.ok) {
      return {
        isValid: false,
        error: intentBinding.error,
        details: {
          chainLength: 1 + (receiptV1.proof.secondary_anchors?.length ?? 0),
          pillarsValidated: pillars.pillarsValidated,
        },
      };
    }
  }

  if (receiptV1.causal_lineage) {
    const lineageBinding = verifyCausalLineageLedgerBinding(receiptV1, options.ledgerDocument ?? null);
    if (!lineageBinding.ok) {
      return {
        isValid: false,
        error: lineageBinding.error,
        details: {
          chainLength: 1 + (receiptV1.proof.secondary_anchors?.length ?? 0),
          pillarsValidated: pillars.pillarsValidated,
        },
      };
    }
  }

  if (receiptV1.partial_path) {
    const pathCheck = verifyPartialPathCommitment(receiptV1.partial_path);
    if (!pathCheck.ok) {
      return {
        isValid: false,
        error: `partial_path verification failed: ${pathCheck.code}`,
        details: {
          chainLength: 1 + (receiptV1.proof.secondary_anchors?.length ?? 0),
          pillarsValidated: pillars.pillarsValidated,
        },
      };
    }
  }

  const anchors = verifyAnchorHashChain(receiptV1);
  if (!anchors.ok) {
    return {
      isValid: false,
      error: anchors.error,
      details: { chainLength: anchors.chainLength, pillarsValidated: pillars.pillarsValidated },
    };
  }

  if (options.strictPolicyVersionHash !== false) {
    const policyHash = verifyPolicyVersionHash(receiptV1);
    if (!policyHash.ok) {
      return {
        isValid: false,
        error: policyHash.error,
        details: { chainLength: anchors.chainLength, pillarsValidated: pillars.pillarsValidated },
      };
    }
  }

  const sig = verifyIntegritySignatures(receiptV1, options.issuerPublicKey);
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
