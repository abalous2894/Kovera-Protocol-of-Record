/**
 * Aevesa gateway-decision/v1 — stable event hash for offline prove-bundle verify.
 * Must stay aligned with private-backend gatewayAttestIngestService.computeGatewayEventHash.
 */

import { sha256Utf8 } from './sha256.js';

/**
 * @param {unknown} raw
 * @returns {Record<string, unknown> | null}
 */
export function normalizeGatewayDecisionEventForHash(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const src = /** @type {Record<string, unknown>} */ (raw);

  const gatewayDecisionId = String(src.gateway_decision_id ?? src.gatewayDecisionId ?? '').trim();
  const gatewaySource = String(src.gateway_source ?? src.gatewaySource ?? '').trim();
  const decision = String(src.decision ?? '').trim().toLowerCase();

  if (!gatewayDecisionId || !gatewaySource || !['permit', 'deny'].includes(decision)) {
    return null;
  }

  return {
    gateway_decision_id: gatewayDecisionId,
    gateway_source: gatewaySource,
    decision,
    evaluated_at:
      typeof src.evaluated_at === 'string' && src.evaluated_at.trim()
        ? src.evaluated_at.trim()
        : typeof src.evaluatedAt === 'string' && src.evaluatedAt.trim()
          ? src.evaluatedAt.trim()
          : null,
    identity:
      src.identity && typeof src.identity === 'object' && !Array.isArray(src.identity)
        ? src.identity
        : null,
    tool:
      src.tool && typeof src.tool === 'object' && !Array.isArray(src.tool) ? src.tool : null,
    data_classification_tag:
      typeof src.data_classification_tag === 'string'
        ? src.data_classification_tag
        : src.data_classification_tag === null
          ? null
          : typeof src.dataClassificationTag === 'string'
            ? src.dataClassificationTag
            : src.data_classification_tag === undefined && src.dataClassificationTag === undefined
              ? null
              : src.data_classification_tag ?? src.dataClassificationTag ?? null,
    policy_reference:
      typeof src.policy_reference === 'string'
        ? src.policy_reference
        : src.policy_reference === null
          ? null
          : typeof src.policyReference === 'string'
            ? src.policyReference
            : src.policy_reference === undefined && src.policyReference === undefined
              ? null
              : src.policy_reference ?? src.policyReference ?? null,
  };
}

/**
 * Stable SHA-256 over canonical gateway event (excludes Aevesa ledger fields).
 * @param {unknown} raw — aevesa.gateway-decision/v1 shaped event
 * @returns {string | null}
 */
export function computeGatewayEventHash(raw) {
  const event = normalizeGatewayDecisionEventForHash(raw);
  if (!event) return null;

  const preimage = JSON.stringify({
    gateway_decision_id: event.gateway_decision_id,
    gateway_source: event.gateway_source,
    decision: event.decision,
    evaluated_at: event.evaluated_at ?? null,
    identity: event.identity ?? null,
    tool: event.tool ?? null,
    data_classification_tag: event.data_classification_tag ?? null,
    policy_reference: event.policy_reference ?? null,
  });

  return sha256Utf8(preimage);
}
