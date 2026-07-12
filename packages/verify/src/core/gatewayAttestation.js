/**
 * Aevesa Proof Moat Phase 1 — gateway attestation digest binding for liability-receipt/v1.
 */

/**
 * @param {unknown} raw
 * @returns {Record<string, unknown> | null}
 */
export function canonicalizeGatewayAttestationForDigest(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

  const src = /** @type {Record<string, unknown>} */ (raw);
  const gatewayDecisionId = String(src.gateway_decision_id ?? src.gatewayDecisionId ?? '').trim();
  const gatewaySource = String(src.gateway_source ?? src.gatewaySource ?? '').trim();
  const decision = String(src.decision ?? '').trim().toLowerCase();

  if (!gatewayDecisionId || !gatewaySource || !['permit', 'deny'].includes(decision)) {
    return null;
  }

  /** @type {Record<string, unknown>} */
  const out = {
    gateway_decision_id: gatewayDecisionId,
    gateway_source: gatewaySource,
    decision,
  };

  const eventHash = String(src.gateway_event_hash ?? src.gatewayEventHash ?? '')
    .trim()
    .toLowerCase();
  if (/^[a-f0-9]{64}$/.test(eventHash)) {
    out.gateway_event_hash = eventHash;
  }

  const tag = src.data_classification_tag ?? src.dataClassificationTag;
  if (typeof tag === 'string' && tag.trim()) {
    out.data_classification_tag = tag.trim();
  }

  const policyRef = src.policy_reference ?? src.policyReference;
  if (typeof policyRef === 'string' && policyRef.trim()) {
    out.policy_reference = policyRef.trim();
  }

  const evaluatedAt = src.evaluated_at ?? src.evaluatedAt;
  if (typeof evaluatedAt === 'string' && evaluatedAt.trim()) {
    out.evaluated_at = evaluatedAt.trim();
  }

  return out;
}
