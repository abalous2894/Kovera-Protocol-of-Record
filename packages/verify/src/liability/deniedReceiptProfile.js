/**
 * Wave 2.2 — DENIED receipt profile on liability-receipt/v1.
 * Verifiable pre-execution refusal evidence (gateway deny, PEP block, runtime firewall).
 */

export const RECEIPT_PROFILE_DENIED = 'DENIED';
export const RECEIPT_PROFILE_PERMITTED = 'PERMITTED';
export const SCITT_REFUSAL_PROFILE = 'SCITT-refusal-event-draft-01';

/**
 * @param {object} receipt
 */
export function isDeniedReceiptProfile(receipt) {
  return receipt?.receipt_profile === RECEIPT_PROFILE_DENIED;
}

/**
 * @param {object} receipt
 */
export function validateDeniedReceiptProfile(receipt) {
  if (!isDeniedReceiptProfile(receipt)) {
    return { ok: true, code: 'NOT_DENIED_PROFILE', skipped: true };
  }

  const errors = [];
  if (receipt.session?.outcome !== 'blocked') {
    errors.push('session.outcome must be blocked');
  }
  if (receipt.policy?.decision !== 'deny') {
    errors.push('policy.decision must be deny');
  }
  if (receipt.denial?.pre_execution !== true) {
    errors.push('denial.pre_execution must be true');
  }
  if (receipt.denial?.execution_occurred !== false) {
    errors.push('denial.execution_occurred must be false');
  }
  if (!receipt.side_effects?.blocked_reason) {
    errors.push('side_effects.blocked_reason is required');
  }

  if (errors.length) {
    return { ok: false, code: 'DENIED_PROFILE_INVALID', errors };
  }

  return { ok: true, code: 'DENIED_PROFILE_VALID' };
}

/**
 * @param {object} receipt
 */
export function buildDeniedReceiptProofSteps(receipt) {
  const profile = validateDeniedReceiptProfile(receipt);
  return [
    {
      key: 'denied_profile',
      label: 'DENIED receipt profile (pre-execution refusal)',
      ok: isDeniedReceiptProfile(receipt),
      detail: receipt.receipt_profile || 'missing',
    },
    {
      key: 'pre_execution',
      label: 'No side effect executed before denial record',
      ok: receipt.denial?.pre_execution === true && receipt.denial?.execution_occurred === false,
      detail: receipt.denial?.denial_stage || 'unspecified',
    },
    {
      key: 'gateway_or_pep',
      label: 'Gateway attest or PEP block bound to receipt',
      ok: Boolean(receipt.gateway_attestation?.decision === 'deny' || receipt.denial?.denial_stage),
      detail: receipt.gateway_attestation?.gateway_decision_id || receipt.denial?.denial_stage || null,
    },
    {
      key: 'denied_invariants',
      label: 'DENIED profile invariants (blocked outcome + deny decision)',
      ok: profile.ok === true,
      detail: profile.ok ? profile.code : profile.errors?.join('; '),
    },
    {
      key: 'scitt_refusal',
      label: 'SCITT refusal-event draft alignment metadata',
      ok: receipt.refusal_alignment?.profile === SCITT_REFUSAL_PROFILE,
      detail: receipt.refusal_alignment?.reference || 'not mapped',
    },
  ];
}

export default {
  RECEIPT_PROFILE_DENIED,
  RECEIPT_PROFILE_PERMITTED,
  SCITT_REFUSAL_PROFILE,
  isDeniedReceiptProfile,
  validateDeniedReceiptProfile,
  buildDeniedReceiptProofSteps,
};
