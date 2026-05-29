import { canonicalize } from './canonicalize.js';

/**
 * Financial / policy / forensic fields bound into the entryHash preimage (aegis/1).
 * Identical to resolveGovernanceBinding() in aegisTrust.js.
 */
export function resolveGovernanceBinding({
  cost,
  approverId,
  policyId,
  forensicSnapshot,
  proofOfIntent,
  normalizedPayload,
}) {
  const rawCost = cost !== undefined && cost !== null ? cost : normalizedPayload?.cost;
  const rawApprover = approverId !== undefined && approverId !== null ? approverId : normalizedPayload?.approverId;
  const rawPolicy = policyId !== undefined && policyId !== null ? policyId : normalizedPayload?.policyId;
  const rawForensic =
    forensicSnapshot !== undefined && forensicSnapshot !== null
      ? forensicSnapshot
      : normalizedPayload?.forensicSnapshot;
  const rawProofOfIntent =
    proofOfIntent !== undefined && proofOfIntent !== null ? proofOfIntent : normalizedPayload?.proofOfIntent;

  const forHash = {
    cost: rawCost != null ? canonicalize(rawCost) : null,
    approverId: rawApprover != null && String(rawApprover) !== '' ? String(rawApprover) : null,
    policyId: rawPolicy != null && String(rawPolicy) !== '' ? String(rawPolicy) : null,
    forensicSnapshot:
      rawForensic == null
        ? null
        : typeof rawForensic === 'object'
          ? canonicalize(rawForensic)
          : { _scalar: String(rawForensic) },
  };
  if (rawProofOfIntent != null && String(rawProofOfIntent).trim() !== '') {
    forHash.proofOfIntent = String(rawProofOfIntent).trim().toLowerCase();
  }
  return { forHash, rawCost, rawApprover, rawPolicy, rawForensic, rawProofOfIntent };
}
