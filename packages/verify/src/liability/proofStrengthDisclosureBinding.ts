import { isRecord } from '../core/isRecord.js';
import { verifyProofStrengthDisclosure } from './proofStrengthDisclosureVerify.js';

const HEX64 = /^[a-f0-9]{64}$/;

function normalizeHex64(value: unknown): string | null {
  const s = String(value ?? '').trim().toLowerCase();
  return HEX64.test(s) ? s : null;
}

/** Extract proof-strength disclosure from receipt governance or legacy top-level field. */
export function extractProofStrengthDisclosureFromReceipt(receipt: unknown): unknown | null {
  if (!isRecord(receipt)) return null;
  const topLevel = receipt.proof_strength_disclosure;
  if (isRecord(topLevel)) return topLevel;
  const governance = receipt.governance;
  if (isRecord(governance) && isRecord(governance.proof_strength_disclosure)) {
    return governance.proof_strength_disclosure;
  }
  return null;
}

/**
 * Stamp digest-bound field from verified governance disclosure (call before sealing receipt_digest).
 * @returns true when binding was applied
 */
export function applyProofStrengthDisclosureDigestBinding(receipt: Record<string, unknown>): boolean {
  const disclosure = extractProofStrengthDisclosureFromReceipt(receipt);
  if (!disclosure) {
    delete receipt.proof_strength_disclosure_digest;
    return false;
  }
  const verified = verifyProofStrengthDisclosure(disclosure);
  if (!verified.ok) return false;
  const digest = normalizeHex64((disclosure as { disclosure_digest?: unknown }).disclosure_digest);
  if (!digest) return false;
  receipt.proof_strength_disclosure_digest = digest;
  return true;
}

export interface ProofStrengthDisclosureBindingResult {
  ok: boolean;
  code?: string;
  error?: string;
}

/**
 * PC-08 — cross-bind digest-excluded governance disclosure to receipt digest pillar.
 * Legacy receipts without `proof_strength_disclosure_digest` still verify when governance is present.
 */
export function verifyProofStrengthDisclosureReceiptBinding(
  receipt: Record<string, unknown>,
): ProofStrengthDisclosureBindingResult {
  const bound = normalizeHex64(receipt.proof_strength_disclosure_digest);
  const disclosure = extractProofStrengthDisclosureFromReceipt(receipt);

  if (!bound && !disclosure) {
    return { ok: true };
  }

  if (bound && !disclosure) {
    return {
      ok: false,
      code: 'DISCLOSURE_BINDING_ORPHAN',
      error:
        'proof_strength_disclosure_digest is present but no verifiable proof_strength_disclosure block was found on the receipt',
    };
  }

  const verified = verifyProofStrengthDisclosure(disclosure);
  if (!verified.ok) {
    if (bound) {
      return {
        ok: false,
        code: 'DISCLOSURE_BINDING_UNVERIFIED',
        error: 'proof_strength_disclosure_digest present but governance disclosure failed verification',
      };
    }
    return { ok: true };
  }

  const expected = normalizeHex64((disclosure as { disclosure_digest?: unknown }).disclosure_digest);
  if (!expected) {
    return {
      ok: false,
      code: 'DISCLOSURE_DIGEST_MISSING',
      error: 'verified proof_strength_disclosure missing disclosure_digest',
    };
  }

  if (!bound) {
    return { ok: true };
  }

  if (bound !== expected) {
    return {
      ok: false,
      code: 'DISCLOSURE_BINDING_MISMATCH',
      error: 'proof_strength_disclosure_digest does not match verified governance disclosure_digest',
    };
  }

  return { ok: true };
}

/**
 * When set-completeness manifest member rows carry disclosure digests, align to member receipts.
 */
export function verifyManifestMemberDisclosureDigests(
  manifest: Record<string, unknown>,
  memberReceipts: unknown[],
): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  const members = Array.isArray(manifest.members) ? manifest.members : [];
  const sorted = [...members].sort(
    (a, b) => Number((a as { step_index?: number }).step_index) - Number((b as { step_index?: number }).step_index),
  );

  for (let i = 0; i < sorted.length; i += 1) {
    const member = sorted[i];
    if (!isRecord(member)) continue;
    const manifestDigest = normalizeHex64(member.proof_strength_disclosure_digest);
    if (!manifestDigest) continue;

    const receipt = memberReceipts[i];
    if (!isRecord(receipt)) {
      errors.push(`member step ${i}: manifest proof_strength_disclosure_digest without receipt`);
      continue;
    }
    const receiptDigest = normalizeHex64(receipt.proof_strength_disclosure_digest);
    if (receiptDigest !== manifestDigest) {
      errors.push(
        `member step ${i}: manifest proof_strength_disclosure_digest ${manifestDigest} !== receipt ${receiptDigest ?? 'absent'}`,
      );
    }
    const binding = verifyProofStrengthDisclosureReceiptBinding(receipt);
    if (!binding.ok) {
      errors.push(`member step ${i}: ${binding.error || binding.code || 'disclosure binding failed'}`);
    }
  }

  return { ok: errors.length === 0, errors };
}
